#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <assert.h>

#include <stdio.h>

#include <sys/types.h>
#include <fcntl.h>
#include <netinet/in.h>

#include <stdint.h>
typedef uint8_t         __u8;
typedef uint16_t        __u16;
typedef int16_t         __s16;
typedef uint32_t        __u32;
typedef int32_t         __s32;
typedef uint64_t        __u64;

#include <netlink/netlink.h>
#include <netlink/addr.h>
int nl_addr_fill_sockaddr(struct nl_addr *addr, struct sockaddr *sa,
                          socklen_t *salen);
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <netlink/cache.h>

#include "ezirad.h"


static struct nl_handle *nlh = NULL;
static struct nl_cache *link_cache = NULL;
static struct nl_cache *addr_cache = NULL;


int ezsys_init (void)
{
	assert (nlh == NULL);

	nlh = nl_handle_alloc ();
	if (nlh != NULL)
	{
		nl_disable_sequence_check (nlh);
		nl_join_groups(nlh, RTMGRP_LINK);
		nl_join_groups (nlh, RTMGRP_IPV6_IFADDR);
	
		if (nl_connect (nlh, NETLINK_ROUTE) == 0)
		{
			link_cache = rtnl_link_alloc_cache (nlh);
			if (link_cache != NULL)
			{
				nl_cache_mngt_provide (link_cache);
				addr_cache = rtnl_addr_alloc_cache (nlh);
	
				if (addr_cache != NULL)
				{
					int fd = nl_handle_get_fd (nlh);
					fcntl (fd, F_SETFL, fcntl (fd, F_GETFL) | O_NONBLOCK);
					return fd;
				}
				nl_cache_free (link_cache);
			}
			nl_close (nlh);
		}
		nl_handle_destroy (nlh);
	}
	return -1;
}


void ezsys_deinit (void)
{
	if (nlh == NULL)
		return;

	nl_cache_free (addr_cache);
	nl_cache_mngt_unprovide (link_cache);
	nl_cache_free (link_cache);
	nl_close (nlh);
	nl_handle_destroy (nlh);
	nlh = NULL;
}


void ezsys_process (void)
{
	assert (nlh != NULL);
	nl_recvmsgs_def (nlh);

	struct nl_dump_params params =
	{ .dp_fd = stdout, .dp_type = NL_DUMP_BRIEF };
	nl_cache_update (nlh, link_cache);
	nl_cache_dump (link_cache, &params);

	nl_cache_update (nlh, addr_cache);
	nl_cache_dump (addr_cache, &params);
	puts ("");
}


void ezsys_getdatasize (unsigned *restrict niface, unsigned *restrict naddr)
{
	*niface = nl_cache_nitems (link_cache);
	*naddr = nl_cache_nitems (addr_cache);
}


void ezsys_getdata (unsigned *restrict ifaces, ez_prefix_t *restrict addrs)
{
	for (struct nl_object *o = nl_cache_get_first (link_cache);
	     o != NULL;
	     o = nl_cache_get_next (o))
	{
		struct rtnl_link *rtl = (struct rtnl_link *)o;
		*ifaces++ = rtnl_link_get_ifindex (rtl);
	}

	for (struct nl_object *o = nl_cache_get_first (addr_cache);
	     o != NULL;
	     o = nl_cache_get_next (o))
	{
		struct rtnl_addr *rta = (struct rtnl_addr *)o;
		if (rtnl_addr_get_family (rta) != AF_INET6)
			continue;

		struct nl_addr *a = rtnl_addr_get_local (rta);
		if (a == NULL)
			continue;

		socklen_t len = sizeof (addrs->addr);
		if (nl_addr_fill_sockaddr (a, (struct sockaddr *)&addrs->addr, &len)
		 || (len < sizeof (addrs->addr)))
			continue;

		if (IN6_IS_ADDR_V4MAPPED (&addrs->addr.sin6_addr)
		 || IN6_IS_ADDR_V4COMPAT (&addrs->addr.sin6_addr))
			continue;

		addrs->addr.sin6_scope_id = rtnl_addr_get_ifindex (rta);
		addrs->prefix_length = nl_addr_get_prefixlen (a);

		addrs++;
	}
}


uint32_t ezsys_get_mtu (int ifindex)
{
	struct rtnl_link *link = rtnl_link_get (link_cache, ifindex);
	if (link == NULL)
		return 0;

	uint32_t mtu = rtnl_link_get_mtu (link);
	rtnl_link_put (link);
	return mtu;
}


size_t ezsys_get_hwaddr (int ifindex, uint8_t *restrict buf, size_t buflen)
{
	struct rtnl_link *link = rtnl_link_get (link_cache, ifindex);
	if (link == NULL)
		return 0;

	struct nl_addr *addr = rtnl_link_get_addr (link);
	unsigned alen = 0;
	if (addr != NULL)
	{
		alen = nl_addr_get_len (addr);
		void *data = nl_addr_get_binary_addr (addr);
		memcpy (buf, data, (alen < buflen) ? alen : buflen);
	}
	rtnl_link_put (link);
	return alen;
}
