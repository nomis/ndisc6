/*
 * rdnssd.c - daemon for DNS configuration from ICMPv6 RA
 * $Id$
 */

/*************************************************************************
 *  Copyright © 2007 Rémi Denis-Courmont.                                *
 *  This program is free software: you can redistribute and/or modify    *
 *  it under the terms of the GNU General Public License as published by *
 *  the Free Software Foundation, versions 2 or 3 of the license.        *
 *                                                                       *
 *  This program is distributed in the hope that it will be useful,      *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of       *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        *
 *  GNU General Public License for more details.                         *
 *                                                                       *
 *  You should have received a copy of the GNU General Public License    *
 *  along with this program. If not, see <http://www.gnu.org/licenses/>. *
 *************************************************************************/

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>
#include <time.h>
#include <stdlib.h>

#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#ifndef NDEBUG
# include <arpa/inet.h>
# include <stdio.h>
#endif


static time_t now;


typedef struct
{
	struct sockaddr_in6 addr;
	time_t              expiry;
} rdnss_t;

#define MAX_RDNSS 3

static struct
{
	size_t  count;
	rdnss_t list[MAX_RDNSS];
} servers = { .count = 0 };


int rdnss_older (const void *a, const void *b)
{
	time_t ta = ((const rdnss_t *)a)->expiry;
	time_t tb = ((const rdnss_t *)b)->expiry;
	
	if (ta > tb)
		return 1;
	if (ta < tb)
		return -1;
	return 0;
}


static void rdnss_update (const struct sockaddr_in6 *addr, time_t expiry)
{
	size_t i;

	/* Does this entry already exist? */
	for (i = 0; i < MAX_RDNSS; i++)
	{
		if (memcmp (addr, &servers.list[i].addr, sizeof (*addr)) == 0)
			break;
	}

	/* Add a new entry */
	if (i == MAX_RDNSS)
	{
		if (expiry == now)
			return; /* Do not add already expired entry! */

		if (servers.count < MAX_RDNSS)
			i = servers.count++;
		else
		{
			/* No more room? replace the most obsolete entry */
			if ((expiry - servers.list[MAX_RDNSS - 1].expiry) >= 0)
				i = MAX_RDNSS - 1;
		}
	}

	memcpy (&servers.list[i].addr, addr, sizeof (*addr));
	servers.list[i].expiry = expiry;

	qsort (servers.list, servers.count, sizeof (rdnss_t), rdnss_older);

#ifndef NDEBUG
	for (unsigned i = 0; i < servers.count; i++)
	{
		char buf[INET6_ADDRSTRLEN];
		inet_ntop (AF_INET6, &servers.list[i].addr.sin6_addr, buf,
		           sizeof (buf));
		printf ("%u: %48s expires at %u\n", i, buf,
		        (unsigned)servers.list[i].expiry);
	}
#endif
}


static int rdnssd (void)
{
	int fd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (fd == -1)
	{
		syslog (LOG_CRIT, "cannot open ICMPv6 socket");
		return -1;
	}

	fcntl (fd, F_SETFD, FD_CLOEXEC);

	/* set ICMPv6 filter */
	{
		struct icmp6_filter f;

		ICMP6_FILTER_SETBLOCKALL (&f);
		ICMP6_FILTER_SETPASS (ND_ROUTER_ADVERT, &f);
		setsockopt (fd, SOL_ICMPV6, ICMP6_FILTER, &f, sizeof (f));
	}

	setsockopt (fd, SOL_IPV6, IPV6_RECVHOPLIMIT, &(int){ 1 }, sizeof (int));
	setsockopt (fd, SOL_IPV6, IPV6_CHECKSUM, &(int){ 2 }, sizeof (int));

	for (;;)
	{
		struct nd_router_advert icmp6;
		uint8_t buf[65536 - sizeof (icmp6)], cbuf[CMSG_SPACE (sizeof (int))];
		struct iovec iov[2] =
		{
			{ .iov_base = &icmp6, .iov_len = sizeof (icmp6) },
			{ .iov_base = buf, .iov_len = sizeof (buf) }
		};
		struct sockaddr_in6 src;
		struct msghdr msg =
		{
			.msg_iov = iov,
			.msg_iovlen = sizeof (iov) / sizeof (iov[0]),
			.msg_name = &src,
			.msg_namelen = sizeof (src),
			.msg_control = cbuf,
			.msg_controllen = sizeof (cbuf)
		};

		ssize_t len = recvmsg (fd, &msg, 0);

		/* Sanity checks */
		if ((len < (ssize_t)sizeof (icmp6)) /* error or too small packet */
		 || (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) /* truncated packet */
		 || !IN6_IS_ADDR_LINKLOCAL (&src.sin6_addr) /* bad source address */
		 || (icmp6.nd_ra_code != 0)) /* unknown ICMPv6 code */
			continue;
		else
		{
			struct timespec ts;
			clock_gettime (CLOCK_MONOTONIC, &ts);
			now = ts.tv_sec;
		}

		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR (&msg);
		     cmsg != NULL;
		     cmsg = CMSG_NXTHDR (&msg, cmsg))
		{
			if ((cmsg->cmsg_level == IPPROTO_IPV6)
			 && (cmsg->cmsg_type == IPV6_HOPLIMIT)
			 && (255 != *(int *)CMSG_DATA (cmsg)))  /* illegal hop limit */
				goto bad;
		}

		/* Parses RA options */
		len -= sizeof (icmp6);
		for (const uint8_t *ptr = buf;
		     (ptr - buf) < len;
		     ptr += (ptr[1] << 3))
		{
			ssize_t optlen = ptr[1];
			uint32_t lifetime;

			if ((optlen == 0) /* illegal option len */
			 || (ptr + (optlen << 3) > buf + len)) /* overflowing length */
				goto bad;

			if (ptr[0] != 25)
				continue;

			/* We have a DNS option! */
			if (((optlen & 1) == 0) /* bad (even) length */
			 || (optlen < 3)) /* too short */
				continue;

			/* Extract DNS servers */
			memcpy (&lifetime, ptr + 4, 4);
			lifetime = ntohl (lifetime);

			do
			{
				struct sockaddr_in6 srv;

				memset (&srv, 0, sizeof (srv));
				srv.sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
				srv.sin6_len = sizeof (srv);
#endif
				srv.sin6_port = htons (53);

				optlen -= 2;
				memcpy (&srv.sin6_addr, ptr + (optlen << 3), 16);
				if (IN6_IS_ADDR_LINKLOCAL (&srv.sin6_addr))
					srv.sin6_scope_id = src.sin6_scope_id;

				rdnss_update (&srv, now + lifetime);
			}
			while (optlen >= 2);
		}

	bad:
		continue;
	}
}


int main (void)
{
	int val;

	openlog ("rrdnsd", LOG_PERROR | LOG_PID, LOG_DAEMON);
	val = rdnssd ();
	closelog ();
	return val != 0;
}
