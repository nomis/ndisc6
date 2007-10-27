/*
 * rdnssd.c - daemon for DNS configuration from ICMPv6 RA
 * $Id$
 */

/*************************************************************************
 *  Copyright © 2007 Rémi Denis-Courmont, Pierre Ynard.                  *
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
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <poll.h>
#include <errno.h>
#include <resolv.h>
#include <sys/inotify.h>
#include <sys/wait.h>


/* Belongs in <netinet/icmp6.h> */

#define ND_OPT_RDNSS 25

struct nd_opt_rdnss {
	uint8_t nd_opt_rdnss_type;
	uint8_t nd_opt_rdnss_len;
	uint16_t nd_opt_rdnss_resserved1;
	uint32_t nd_opt_rdnss_lifetime;
	/* followed by one or more IPv6 addresses */
};

/* Belongs in <linux/rtnetlink.h> */

struct nduseroptmsg
{
	unsigned char	nduseropt_family;
	unsigned char	nduseropt_pad1;
	unsigned short	nduseropt_opts_len; /* Total length of options */
	__u8		nduseropt_icmp_type;
	__u8		nduseropt_icmp_code;
	unsigned short	nduseropt_pad2;
	/* Followed by one or more ND options */
};

#define RTNLGRP_ND_USEROPT 20


static time_t now;


typedef struct
{
	struct in6_addr addr;
	time_t          expiry;
} rdnss_t;

#define MAX_RDNSS MAXNS

static struct
{
	size_t  count;
	rdnss_t list[MAX_RDNSS];
} servers = { .count = 0 };

void merge_hook()
{
	int status;

	if (fork() == 0) {
		execv("/etc/rdnssd/merge.hook", NULL);
		exit(1);
	}

	wait(&status);

}

void write_resolv()
{
	FILE *resolv = fopen("/var/run/rdnssd/resolv.conf", "w");

	if (! resolv) {
		syslog(LOG_ERR, "cannot write resolv.conf: %s", strerror(errno));
		return;
	}

	for (size_t i = 0; i < servers.count; i++) {
		char buf[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &servers.list[i].addr, buf, INET6_ADDRSTRLEN);
		fputs("nameserver ", resolv);
		fputs(buf, resolv);
		fputs("\n", resolv);
	}

	fclose(resolv);

}

void trim_expired()
{
	while (servers.count > 0
	       && servers.list[servers.count - 1].expiry <= now)
		servers.count--;
}

int rdnss_older (const void *a, const void *b)
{
	time_t ta = ((const rdnss_t *)a)->expiry;
	time_t tb = ((const rdnss_t *)b)->expiry;

	if (ta < tb)
		return 1;
	if (ta > tb)
		return -1;
	return 0;
}

static void rdnss_update (const struct in6_addr *addr, time_t expiry)
{
	size_t i;

	/* Does this entry already exist? */
	for (i = 0; i < servers.count; i++)
	{
		if (memcmp (addr, &servers.list[i].addr, sizeof (*addr)) == 0)
			break;
	}

	/* Add a new entry */
	if (i == servers.count)
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
		inet_ntop (AF_INET6, &servers.list[i].addr, buf,
		           sizeof (buf));
		printf ("%u: %48s expires at %u\n", i, buf,
		        (unsigned)servers.list[i].expiry);
	}
#endif
}

static int parse_nd_opts(struct nd_opt_hdr *opt, unsigned int opts_len)
{

	for (; opts_len >= sizeof(struct nd_opt_hdr);
	     opts_len -= opt->nd_opt_len << 3,
	     opt = (struct nd_opt_hdr *)
		   ((uint8_t *) opt) + (opt->nd_opt_len << 3)) {
		struct nd_opt_rdnss *rdnss_opt;
		ssize_t nd_opt_len = opt->nd_opt_len;
		uint32_t lifetime;

		if (nd_opt_len == 0 || opts_len < nd_opt_len << 3)
			return -1;

		if (opt->nd_opt_type != ND_OPT_RDNSS)
			continue;

		if (nd_opt_len < 3 /* too short per RFC */
			|| (nd_opt_len & 1) == 0) /* bad (even) length */
			continue;

		rdnss_opt = (struct nd_opt_rdnss *) opt;

		{
			struct timespec ts;
			clock_gettime(CLOCK_MONOTONIC, &ts);
			now = ts.tv_sec;
		}

		lifetime = now + ntohl(rdnss_opt->nd_opt_rdnss_lifetime);

		for (struct in6_addr *addr = (struct in6_addr *) (rdnss_opt + 1);
		     nd_opt_len >= 2; addr++, nd_opt_len -= 2)
			rdnss_update(addr, lifetime);

	}

	return 0;

}

#if 0
/* TODO: use this as fallback if netlink is not available */
static int recv_icmp (int fd)
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
			return -1;

		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR (&msg);
		     cmsg != NULL;
		     cmsg = CMSG_NXTHDR (&msg, cmsg))
		{
			if ((cmsg->cmsg_level == IPPROTO_IPV6)
			 && (cmsg->cmsg_type == IPV6_HOPLIMIT)
			 && (255 != *(int *)CMSG_DATA (cmsg)))  /* illegal hop limit */
				return -1;
		}

		/* Parses RA options */
		len -= sizeof (icmp6);
		return parse_nd_opts((struct nd_opt_hdr *) buf, len);

}

static int icmp_socket()
{
	int fd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (fd == -1)
	{
		syslog (LOG_CRIT, "cannot open ICMPv6 socket");
		return -1;
	}

	/* set ICMPv6 filter */
	{
		struct icmp6_filter f;

		ICMP6_FILTER_SETBLOCKALL (&f);
		ICMP6_FILTER_SETPASS (ND_ROUTER_ADVERT, &f);
		setsockopt (fd, SOL_ICMPV6, ICMP6_FILTER, &f, sizeof (f));
	}

	setsockopt (fd, SOL_IPV6, IPV6_RECVHOPLIMIT, &(int){ 1 }, sizeof (int));
	setsockopt (fd, SOL_IPV6, IPV6_CHECKSUM, &(int){ 2 }, sizeof (int));

	return fd;
}
#endif

static int recv_nl (int fd)
{
	unsigned int buf_size = NLMSG_SPACE(65536 - sizeof(struct icmp6_hdr));
	uint8_t buf[buf_size];
	int msg_size;
	struct nduseroptmsg *ndmsg;

	memset(buf, 0, buf_size);
	msg_size = recv(fd, buf, buf_size, 0);
	if (msg_size < 0)
		return -1;

	if (msg_size < NLMSG_SPACE(sizeof(struct nduseroptmsg)))
		return -1;

	ndmsg = (struct nduseroptmsg *) NLMSG_DATA((struct nlmsghdr *) buf);

	if (ndmsg->nduseropt_family != AF_INET6
		|| ndmsg->nduseropt_icmp_type != ND_ROUTER_ADVERT
		|| ndmsg->nduseropt_icmp_code != 0)
		return 0;

	if (msg_size < NLMSG_SPACE(sizeof(struct nduseroptmsg) + ndmsg->nduseropt_opts_len))
		return -1;

	return parse_nd_opts((struct nd_opt_hdr *) (ndmsg + 1), ndmsg->nduseropt_opts_len);

}

#define recv_msg recv_nl

static int nl_socket()
{
	struct sockaddr_nl saddr;
	int fd;
	int rval;

	fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (fd < 0) {
		syslog(LOG_CRIT, "cannot open netlink socket");
		return fd;
	}

	memset(&saddr, 0, sizeof(struct sockaddr_nl));
	saddr.nl_family = AF_NETLINK;
	saddr.nl_pid = getpid();
	saddr.nl_groups = 1 << (RTNLGRP_ND_USEROPT - 1);

	rval = bind(fd, (struct sockaddr *) &saddr, sizeof(struct sockaddr_nl));
	if (rval < 0)
		return rval;

	return fd;
}

#define setup_socket nl_socket

static void prepare_fd (int fd)
{
	fcntl (fd, F_SETFD, FD_CLOEXEC);

	/* be defensive - we want to block on poll(), not recv() */
	fcntl (fd, F_SETFL, fcntl (fd, F_GETFL) | O_NONBLOCK);
}


static int rdnssd (void)
{
	int sock, inofd;

	sock = setup_socket();
	if (sock == -1)
		return -1;
	prepare_fd (sock);

	inofd = inotify_init();
	if (inofd == -1)
	{
		close (sock);
		return -1;
	}
	prepare_fd (inofd);

	for (;;)
	{
		struct pollfd pfd[2] =
		{
			{ .fd = sock,  .events = POLLIN, .revents = 0 },
			{ .fd = inofd, .events = POLLIN, .revents = 0 },
		};
		int timeout;
		{
			struct timespec ts;
			clock_gettime(CLOCK_MONOTONIC, &ts);
			now = ts.tv_sec;
		}

		trim_expired();
		write_resolv();
		merge_hook();

		if (servers.count)
			timeout = 1000 * (servers.list[servers.count - 1].expiry - now);
		else
			timeout = -1;

		inotify_add_watch(pfd[1].fd, "/etc/resolv.conf", IN_MODIFY);

		if (poll (pfd, sizeof (pfd) / sizeof (pfd[0]), timeout) <= 0)
			continue;

		if (pfd[0].revents & POLLIN)
			recv_msg(sock);
		if (pfd[1].revents & POLLIN) {
			struct inotify_event ie;
			read(inofd, &ie, sizeof(ie));
		}
	}
}


int main (void)
{
	int val;

	openlog ("rdnssd", LOG_PERROR | LOG_PID, LOG_DAEMON);
	val = rdnssd ();
	closelog ();
	return val != 0;
}
