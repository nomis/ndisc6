#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <net/if.h>

#ifndef IPV6_RECVPKTINFO
# define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif
#ifndef IPV6_RECVHOPLIMIT
# define IPV6_RECVHOPLIMIT IPV6_HOPLIMIT
#endif

#include "ezirad.h"


static int
recv_rs (int fd, struct sockaddr_in6 *restrict src,
         struct sockaddr_in6 *restrict dst)
{
	struct nd_router_solicit icmp;
	uint8_t opts[1280 - sizeof (struct nd_router_solicit)];
	char cbuf[CMSG_SPACE (sizeof (struct in6_pktinfo))
	          + CMSG_SPACE (sizeof (int))];
	struct iovec iov[] =
	{
		{
			.iov_base = &icmp,
			.iov_len = sizeof (icmp)
		},
		{
			.iov_base = opts,
			.iov_len = sizeof (opts)
		}
	};
	struct msghdr msg =
	{
		.msg_name = (struct sockaddr *)src,
		.msg_namelen = sizeof (*src),
		.msg_iov = iov,
		.msg_iovlen = sizeof (iov) / sizeof (iov[0]),
		.msg_control = cbuf,
		.msg_controllen = sizeof (cbuf)
	};

	/* Receive router solicitation */
	ssize_t val = recvmsg (fd, &msg, 0);
	if (val == -1)
		return -1;

	/* Validate router solicitation */
	/* It is assumed checksum was validated by the kernel */
	memset (dst, 0, sizeof (*dst));
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR (&msg);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR (&msg, cmsg))
	{
		if (cmsg->cmsg_level != IPPROTO_IPV6)
			continue;

		switch (cmsg->cmsg_type)
		{
			/* Ignore packets with incorrect hop limit */
			case IPV6_HOPLIMIT:
				if (255 != *(int *)CMSG_DATA (cmsg))
					goto error;
				break;

			case IPV6_PKTINFO:
			{
				const struct in6_pktinfo *nfo =
					(struct in6_pktinfo *)CMSG_DATA (cmsg);
				dst->sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
				dst->sin6_len = sizeof (*dst);
#endif
				dst->sin6_scope_id = nfo->ipi6_ifindex;
				memcpy (&dst->sin6_addr, &nfo->ipi6_addr, 16);
			}
		}
	}

	if (dst->sin6_scope_id == 0)
		goto error;

	val -= sizeof (icmp);
	if ((val < 0)
	 || (icmp.nd_rs_type != ND_ROUTER_SOLICIT)
	 || (icmp.nd_rs_code != 0))
		goto error;

	for (uint8_t *ptr = opts; val >= 8;)
	{
		uint16_t optlen = ptr[1] << 3;

		if (optlen == 0)
			goto error;

		val -= optlen;
		if (val < 0)
			goto error;

		switch (ptr[0])
		{
			case ND_OPT_SOURCE_LINKADDR:
				if (IN6_IS_ADDR_UNSPECIFIED (&src->sin6_addr))
					goto error;
				break;
		}

		ptr += optlen;
	}

	return 0;

error:
	errno = EAGAIN;
	return -1;
}


/**
 * Tries to guess the hop limit for an interface.
 */
static uint8_t guess_hlim (int ifindex)
{
	int hlim = -1;

	int fd = socket (AF_INET6, SOCK_DGRAM, 0);
	if (fd != -1)
	{
		struct in6_pktinfo info =
		{
			.ipi6_ifindex = ifindex
		};

		/* Note: Linux does not currently implements this */
		setsockopt (fd, IPPROTO_IPV6, IPV6_PKTINFO, &info, sizeof (info));

		/* Note: Linux only implements this as of version 2.6.20 */
		if (getsockopt (fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hlim,
		                &(socklen_t){ sizeof (hlim) }))
			hlim = -1;

		close (fd);
	}

	if (hlim == -1)
		hlim = 128;

	return hlim;
}

#define MAX_INITIAL_RTR_ADVERT_INTERVAL 16
#define MAX_INITIAL_RTR_ADVERTISEMENTS   3
#define MAX_FINAL_RTR_ADVERTISEMENTS     3
#define MIN_DELAY_BETWEEN_RAS            3
//#define MAX_RA_DELAY_TIME              .5



typedef struct ez_prefix ez_prefix_t;
typedef struct ez_iface  ez_iface_t;

struct ez_prefix
{
	ez_prefix_t      *next;
	struct in6_addr   prefix;
	unsigned          length;
};

struct ez_iface
{
	ez_iface_t     *next;
	ez_prefix_t    *prefixes;
	unsigned        index;
	struct in6_addr linklocal;
	struct
	{
		struct timespec next;
		struct timespec next_multicast;
		unsigned        initial;
		timer_t         id;
	} timer;
};


static void iface_destroy (ez_iface_t *iface)
{
	/* TODO: send bye */
	timer_delete (iface->timer.id);

	for (ez_prefix_t *p = iface->prefixes; p != NULL;)
	{
		ez_prefix_t *buf = p->next;
		free (p);
		p = buf;
	}
}


static void iface_destroy_all (ez_iface_t *iface)
{
	while (iface != NULL)
	{
		ez_iface_t *buf = iface->next;
		iface_destroy (iface);
		iface = buf;
	}
}


static void

static ez_iface_t *
iface_create (ez_iface_t **list, unsigned ifindex)
{
	ez_iface_t *iface = malloc (sizeof (**list));
	if (iface == NULL)
		return NULL;

	iface->next = *list;
	iface->prefix = NULL;
	iface->index = ifindex;
	iface->initial = MAX_INITIAL_RTR_ADVERTISEMENTS;
	clock_gettime (CLOCK_MONOTONIC, &iface->next

static int send_ra (int fd, const struct sockaddr_in6 *peer,
                    const struct sockaddr_in6 *local)
{
	const unsigned ifindex = local->sin6_scope_id;

	/* RA source address */
	struct in6_addr src = local->sin6_addr;
	ezsys_addr_rewind ();
	while (!IN6_IS_ADDR_LINKLOCAL (&src))
	{
		struct ez_addr p;
		if (ezsys_addr_read (&p) == NULL)
		{
			errno = EADDRNOTAVAIL;
			return -1; // could not find suitable source address
		}

		if (p.addr.sin6_scope_id != ifindex)
			continue;

		memcpy (src.s6_addr, p.addr.sin6_addr.s6_addr, 16);
	}

	/* Router advertisement */
	struct nd_router_advert icmp;
	uint8_t optbuf[1280 - (40 + sizeof (struct nd_router_advert))];
	uint8_t *opt = optbuf;
	const uint8_t *optend = optbuf + sizeof (optbuf);

	icmp.nd_ra_type = ND_ROUTER_ADVERT;
	icmp.nd_ra_code = 0;
	icmp.nd_ra_cksum = 0;
	icmp.nd_ra_curhoplimit = guess_hlim (ifindex);
	icmp.nd_ra_flags_reserved = 0x18;
	icmp.nd_ra_router_lifetime = htons (1800);
	icmp.nd_ra_reachable = 0;
	icmp.nd_ra_retransmit = 0;

	/* Source LL option option */
	size_t val = ezsys_get_hwaddr (ifindex, opt + 2, sizeof (optbuf) - 2);
	if ((val > 0) && (val < (0x800 - 2) /* max option length */))
	{
		val += 2;
		uint16_t optlen = (val + 7) & ~7;
		opt[0] = ND_OPT_SOURCE_LINKADDR;
		opt[1] = optlen >> 3;
		assert (optlen >= val);
		memset (opt + val, 0, optlen - val);
		opt += optlen;
	}

#if 0
	/* MTU option */
	uint32_t mtu = ezsys_get_mtu (local->sin6_scope_id);
	if ((mtu >= 1280) && ((optend - opt) >= 8))
	{
		opt[0] = ND_OPT_MTU;
		opt[1] = 1;
		opt[2] = opt[3] = 0;
		memcpy (opt + 4, &(uint32_t){ htonl (mtu) }, 4);
		opt += 8;
	}
#endif

	/* Prefix option(s) */
	ezsys_addr_rewind ();

	for (struct nd_opt_prefix_info *first = (struct nd_opt_prefix_info *)opt;
	     (size_t)(optend - opt) >= sizeof (struct nd_opt_prefix_info);
	     )
	{
		struct ez_addr p;
		if (ezsys_addr_read (&p) == NULL)
			break;

		if ((p.addr.sin6_scope_id != ifindex)
		 || IN6_IS_ADDR_LINKLOCAL (&p.addr.sin6_addr)
		 || (p.prefix_length >= 128))
			continue;

		struct nd_opt_prefix_info *nfo = (struct nd_opt_prefix_info *)opt;
		nfo->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
		nfo->nd_opt_pi_len = sizeof (*nfo) >> 3;
		nfo->nd_opt_pi_prefix_len = p.prefix_length;

		uint8_t flags = ND_OPT_PI_FLAG_ONLINK;
		if (p.prefix_length == 64)
			flags |= ND_OPT_PI_FLAG_AUTO;
		nfo->nd_opt_pi_flags_reserved = flags;
		nfo->nd_opt_pi_valid_time = htonl (2592000);
		nfo->nd_opt_pi_preferred_time = htonl (604800);
		nfo->nd_opt_pi_reserved2 = 0;

		uint8_t i = p.prefix_length >> 3;
		memcpy (nfo->nd_opt_pi_prefix.s6_addr, p.addr.sin6_addr.s6_addr, i);
		memset (nfo->nd_opt_pi_prefix.s6_addr + i, 0, 16 - i);
		if (p.prefix_length & 7)
		{
			uint8_t mask = ((1 << (8 - (p.prefix_length & 7))) - 1) ^ 0xff;
			nfo->nd_opt_pi_prefix.s6_addr[i] |=
				p.addr.sin6_addr.s6_addr[i] & mask;
		}

		/* Make sure we did not already include the same prefix */
		const struct nd_opt_prefix_info *other = first;
		while (other < nfo)
		{
			if (IN6_ARE_ADDR_EQUAL (&other->nd_opt_pi_prefix,
			                        &nfo->nd_opt_pi_prefix)
			 && (other->nd_opt_pi_prefix_len == nfo->nd_opt_pi_prefix_len))
				break;
			other++;
		}
		if (other < nfo)
			continue; // duplicate prefix!

		opt += sizeof (*nfo);
	}

	/* Send */
	char cbuf[CMSG_SPACE (sizeof (struct in6_pktinfo))];
	struct iovec iov[] =
	{
		{
			.iov_base = &icmp,
			.iov_len = sizeof (icmp)
		},
		{
			.iov_base = optbuf,
			.iov_len = opt - optbuf
		}
	};
	struct msghdr msg =
	{
		.msg_name = (struct sockaddr *)peer,
		.msg_namelen = sizeof (*peer),
		.msg_iov = iov,
		.msg_iovlen = sizeof (iov) / sizeof (iov[0]),
		.msg_control = cbuf,
		.msg_controllen = sizeof (cbuf)
	};

	struct cmsghdr *cmsg = CMSG_FIRSTHDR (&msg);
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;
	cmsg->cmsg_len = CMSG_LEN (sizeof (struct in6_pktinfo));

	struct in6_pktinfo *pinfo = (struct in6_pktinfo *)CMSG_DATA (cmsg);
	memcpy (&pinfo->ipi6_ifindex, &local->sin6_scope_id,
	        sizeof (pinfo->ipi6_ifindex));
	memcpy (pinfo->ipi6_addr.s6_addr, src.s6_addr, 16);

	return sendmsg (fd, &msg, 0) > 0 ? 0 : -1;
}


/* TOOD: unsolicited thread */

static int prepare_icmp_socket (int fd)
{
	/* Only process Router Solicitation */
	struct icmp6_filter f;
	ICMP6_FILTER_SETBLOCKALL (&f);
	ICMP6_FILTER_SETPASS (ND_ROUTER_SOLICIT, &f);
	(void)setsockopt (fd, IPPROTO_ICMPV6, ICMP6_FILTER, &f, sizeof (f));

	/* Subscribe to ip6-allrouters */
	struct group_req mr;
	memset (&mr, 0, sizeof (mr));
	mr.gr_group.ss_family = AF_INET6;
#ifdef HAVE_SA_LEN
	mr.gr_group.ss_len = sizeof (struct sockaddr_in6);
#endif
	((struct sockaddr_in6 *)&mr.gr_group)->sin6_addr.s6_addr[0] = 0xff;
	((struct sockaddr_in6 *)&mr.gr_group)->sin6_addr.s6_addr[1] =
	((struct sockaddr_in6 *)&mr.gr_group)->sin6_addr.s6_addr[15] = 0x02;
	setsockopt (fd, IPPROTO_IPV6, MCAST_JOIN_GROUP, &mr, sizeof (mr));

	setsockopt (fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &(int){ 255 },
	            sizeof (int));
	setsockopt (fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &(int){ 255 },
	            sizeof (int));
	setsockopt (fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &(int){ 1 },
	            sizeof (int));
	setsockopt (fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &(int){ 1 },
	            sizeof (int));

	return 0;
}


static int exit_signal = 0;
static void exit_handler (int signum)
{
	exit_signal = signum;
}


static void init_signals (void)
{
	struct sigaction sa;
	sigset_t set;

	memset (&sa, 0, sizeof (sa));
	sigemptyset (&sa.sa_mask);
	sigemptyset (&set);

	sa.sa_handler = exit_handler;
	sigaction (SIGINT, &sa, NULL);
	sigaddset (&set, SIGINT);
	sigaction (SIGQUIT, &sa, NULL);
	sigaddset (&set, SIGQUIT);
	sigaction (SIGTERM, &sa, NULL);
	sigaddset (&set, SIGTERM);

	sa.sa_handler = SIG_IGN;
	sigaction (SIGPIPE, &sa, NULL);
	sigaddset (&set, SIGPIPE);
	sigaction (SIGHUP, &sa, NULL);
	sigaddset (&set, SIGHUP);

	//sigprocmask (SIG_BLOCK, &set, NULL);
}


int main (void)
{
	int retval = 1;
	setgid (65534); // FIXME

	/* ICMPv6 socket initialization */
	int fd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (fd == -1)
	{
		perror (_("ICMPv6 socket"));
		return 1;
	}
	setuid (65534); // FIXME

	init_signals ();

	if (prepare_icmp_socket (fd))
		goto error;

	/* Netlink address cache initialization */
	int nlfd = ezsys_init ();
	if (nlfd == -1)
		goto error;

	while (!exit_signal)
	{
		sigset_t set;
		struct pollfd ufd[] =
		{
			{ .fd = fd, .events = POLLIN },
			{ .fd = nlfd, .events = POLLIN }
		};
		sigemptyset (&set);

#define ppoll( u, n, t, s ) poll( u, n, -1 )

		int val = ppoll (ufd, sizeof (ufd) / sizeof (ufd[0]), NULL, &set);
		if (val == -1)
			continue;

		if (ufd[1].revents)
			ezsys_process ();

		if (ufd[0].revents)
		{
			struct sockaddr_in6 src, dst;
			if (recv_rs (fd, &src, &dst) == 0)
				send_ra (fd, &src, &dst);
			else
				perror ("recv_rs");
		}
	}

	retval = 0;

error:
	ezsys_deinit ();
	close (fd);
	return 0;
}

