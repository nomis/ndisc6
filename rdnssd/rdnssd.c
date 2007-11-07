/*
 * rdnssd.c - daemon for DNS configuration from ICMPv6 RA
 * $Id$
 */

/*************************************************************************
 *  Copyright © 2007 Pierre Ynard, Rémi Denis-Courmont.                  *
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

#include "gettext.h"

#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <locale.h>

#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>
#include <resolv.h>
#include <sys/wait.h>
#include <getopt.h>


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

/* Internal defines */

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

/* The code */

static void write_resolv(const char *resolvpath)
{
	FILE *resolv;
	int rval;
	char tmpfile[strlen(resolvpath) + sizeof(".tmp")];

	sprintf(tmpfile, "%s.tmp", resolvpath);

	resolv = fopen(tmpfile, "w");

	if (! resolv) {
		syslog (LOG_ERR, _("cannot write resolv.conf: %m"));
		return;
	}

	for (size_t i = 0; i < servers.count; i++) {
		char buf[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &servers.list[i].addr, buf, INET6_ADDRSTRLEN);
		fprintf(resolv, "nameserver %s\n", buf);
	}

	fclose(resolv);

	rval = rename(tmpfile, resolvpath);

	if (rval == -1)
		syslog(LOG_ERR, _("cannot write resolv.conf: %m"));

}

static void trim_expired()
{
	while (servers.count > 0
	       && servers.list[servers.count - 1].expiry <= now)
		servers.count--;
}

static int rdnss_older (const void *a, const void *b)
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
		syslog (LOG_DEBUG, "%u: %48s expires at %u\n", i, buf,
		        (unsigned)servers.list[i].expiry);
	}
#endif
}

static int parse_nd_opts (const struct nd_opt_hdr *opt, size_t opts_len)
{
	for (; opts_len >= sizeof(struct nd_opt_hdr);
	     opts_len -= opt->nd_opt_len << 3,
	     opt = (const struct nd_opt_hdr *)
		   ((const uint8_t *) opt) + (opt->nd_opt_len << 3)) {
		struct nd_opt_rdnss *rdnss_opt;
		size_t nd_opt_len = opt->nd_opt_len;
		uint32_t lifetime;

		if (nd_opt_len == 0 || opts_len < (nd_opt_len << 3))
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
		syslog (LOG_CRIT, _("cannot open ICMPv6 socket"));
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
	size_t msg_size;
	struct nduseroptmsg *ndmsg;

	memset(buf, 0, buf_size);
	msg_size = recv(fd, buf, buf_size, 0);
	if (msg_size == (size_t)(-1))
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
		syslog(LOG_CRIT, _("cannot open netlink socket"));
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
	fcntl (fd, F_SETFL, fcntl (fd, F_GETFL) | O_NONBLOCK);
}

static volatile int termsig = 0;

static void term_handler (int signum)
{
	termsig = signum;
}

static void ignore_handler (int signum)
{
	(void)signum;
}

static int worker (const char *resolvpath)
{
	struct sigaction act;
	sigset_t emptyset;
	pid_t ppid = getppid ();
	int sock = setup_socket ();

	if (sock == -1)
		return -1;
	prepare_fd (sock);
	/* be defensive - we want to block on poll(), not recv() */

	memset (&act, 0, sizeof (struct sigaction));
	act.sa_handler = term_handler;

	act.sa_handler = term_handler;
	sigaction (SIGTERM, &act, NULL);

	act.sa_handler = term_handler;
	sigaction (SIGINT, &act, NULL);

	act.sa_handler = ignore_handler;
	sigaction (SIGPIPE, &act, NULL);

	sigemptyset (&emptyset);

	while (termsig == 0)
	{
		struct pollfd pfd =
			{ .fd = sock,  .events = POLLIN, .revents = 0 };
		struct timespec ts;

		clock_gettime (CLOCK_MONOTONIC, &ts);
		now = ts.tv_sec;

		trim_expired();
		write_resolv(resolvpath);
		kill(ppid, SIGUSR1);

		if (servers.count)
			ts.tv_sec = (servers.list[servers.count - 1].expiry - now);
			ts.tv_nsec = 0;

		if (ppoll (&pfd, 1, servers.count ? &ts : NULL, &emptyset) <= 0)
			continue;

		if (pfd.revents)
			recv_msg(sock);
	}

	close (sock);

	servers.count = 0;
	write_resolv(resolvpath);
	return 0;
}

static void merge_hook (const char *hookpath)
{
	pid_t pid = fork ();

	switch (pid)
	{
		case 0:
			execl (hookpath, hookpath, (char *)NULL);
			syslog (LOG_ERR, _("cannot run %s: %m"), hookpath);
			exit(1);

		case -1:
			syslog (LOG_ERR, _("cannot run %s: %m"), hookpath);
			break;

		default:
		{
			int status;
			waitpid (pid, &status, 0);
		}
	}

}

static int rdnssd (const char *resolvpath, const char *hookpath)
{
	int rval = 0;
	sigset_t term_set, handled, orig_mask;
	pid_t worker_pid;

	sigemptyset (&handled);

	sigaddset (&handled, SIGTERM);
	sigaddset (&handled, SIGINT);

	term_set = handled;

	sigaddset (&handled, SIGPIPE);
	sigaddset (&handled, SIGUSR1);

	/* TODO: HUP handling */

	sigprocmask (SIG_BLOCK, &handled, &orig_mask);

	worker_pid = fork();

	switch (worker_pid)
	{
		case 0:
			rval = worker(resolvpath);
			exit(rval != 0);

		case -1:
			syslog (LOG_CRIT, _("cannot fork: %m"));
			rval = -1;
			break;

		default:
			for (;;)
			{
				siginfo_t info;

				sigwaitinfo(&handled, &info);

				if (sigismember(&term_set, info.si_signo))
					break;

				if (hookpath)
					merge_hook(hookpath);
			}

			int status;

			kill (worker_pid, SIGTERM);
			while (waitpid (worker_pid, &status, 0) == -1);

			if (hookpath)
				merge_hook (hookpath);

	}

	sigprocmask (SIG_SETMASK, &orig_mask, NULL);

	return rval;

}


/** PID file handling */
#ifndef O_NOFOLLOW
# define O_NOFOLLOW 0
#endif
static int
open_pidfile (const char *path)
{
	int fd;

	fd = open (path, O_WRONLY|O_CREAT|O_NOFOLLOW, 0644);
	if (fd != -1)
	{
		struct stat s;

		errno = 0;
		if ((fstat (fd, &s) == 0)
		 && S_ISREG(s.st_mode)
		 && (lockf (fd, F_TLOCK, 0) == 0)
		 && (ftruncate (fd, 0) == 0))
			return fd;

		if (errno == 0) /* !S_ISREG */
			errno = EACCES;

		(void)close (fd);
	}
	return -1;
}


static int
write_pid (int fd)
{
	char buf[20]; // enough for > 2^64

	(void)snprintf (buf, sizeof (buf), "%d", (int)getpid ());
	buf[sizeof (buf) - 1] = '\0';
	size_t len = strlen (buf);

	if ((write (fd, buf, len) != (ssize_t)len) || fdatasync (fd))
		return -1;
	return 0;
}


static int
quick_usage (const char *path)
{
	fprintf (stderr, _("Try \"%s -h\" for more information.\n"),
	         path);
	return 2;
}


static int
usage (const char *path)
{
	printf (_(
"Usage: %s TODO\n"
"Starts the IPv6 Recursive DNS Server Discovery daemon.\n"
"\n"
"  -f, --foreground  run in the foreground\n"
/* -H */
"  -h, --help        display this help and exit\n"
"  -p, --pidfile     override the location of the PID file\n"
"  -r, --resolv-file set the path to the generated resolv.conf file\n"
/*"  -u, --user       override the user to set UID to\n"*/
"  -V, --version    display program version and exit\n"), path);
	return 0;
}


static int
version (void)
{
	printf (_("rdnssd: IPv6 Recursive DNS Server Discovery daemon %s (%s)\n"),
	        VERSION, "$Rev$");
	printf (_(" built %s on %s\n"), __DATE__, PACKAGE_BUILD_HOSTNAME);
	printf (_("Configured with: %s\n"), PACKAGE_CONFIGURE_INVOCATION);
	puts (_("Written by Pierre Ynard and Remi Denis-Courmont\n"));

	printf (_("Copyright (C) %u-%u Pierre Ynard, Remi Denis-Courmont\n"),
	        2007, 2007);
	puts (_(
"This is free software; see the source for copying conditions.\n"
"There is NO warranty; not even for MERCHANTABILITY or\n"
"FITNESS FOR A PARTICULAR PURPOSE.\n"));
        return 0;
}


int main (int argc, char *argv[])
{
	const char *hookpath = NULL;
	const char *pidpath = LOCALSTATEDIR "/run/rdnssd.pid";
	const char *resolvpath = LOCALSTATEDIR "/run/rdnssd/resolv.conf";
	int c, pidfd, rval = 1;
	bool fg = false;

	static const struct option opts[] =
	{
		{ "foreground",		no_argument,		NULL, 'f' },
		{ "hook",			required_argument,	NULL, 'H' },
		{ "merge-hook",		required_argument,	NULL, 'H' },
		{ "help",			no_argument,		NULL, 'h' },
		{ "pidfile",		required_argument,	NULL, 'p' },
		{ "resolv-file",	required_argument,	NULL, 'r' },
		{ "version",		no_argument,		NULL, 'V' },
		{ NULL,				no_argument,		NULL, '\0'}
	};
	static const char optstring[] = "fH:hp:r:V";

	setlocale (LC_ALL, "");
	bindtextdomain (PACKAGE, LOCALEDIR);
	textdomain (PACKAGE);

	while ((c = getopt_long (argc, argv, optstring, opts, NULL)) != -1)
	{
		switch (c)
		{
			case 'f':
				fg = true;
				break;

			case 'H':
				hookpath = optarg;
				break;

			case 'h':
				return usage (argv[0]);

			case 'p':
				pidpath = optarg;
				break;

			case 'r':
				resolvpath = optarg;
				break;

			case 'V':
				return version ();

			case '?':
				return quick_usage (argv[0]);
		}
	}

	pidfd = open_pidfile (pidpath);
	if (pidfd == -1)
	{
		fprintf (stderr, _("Cannot create %s (%s) - already running?\n"),
		         pidpath, strerror (errno));
		return 1;
	}

	if (fg || (daemon (0, 0) == 0))
	{
		openlog ("rdnssd", (fg ? LOG_PERROR : 0) | LOG_PID, LOG_DAEMON);

		write_pid (pidfd);
		rval = rdnssd (resolvpath, hookpath);

		closelog ();
	}

	unlink (pidpath);
	close (pidfd);

	return rval != 0;
}
