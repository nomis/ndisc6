/*
 * ndisc.c - ICMPv6 neighbour discovery command line tool
 * $Id$
 */

/***********************************************************************
 *  Copyright (C) 2004 Remi Denis-Courmont.                            *
 *  This program is free software; you can redistribute and/or modify  *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; version 2 of the license.         *
 *                                                                     *
 *  This program is distributed in the hope that it will be useful,    *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.               *
 *  See the GNU General Public License for more details.               *
 *                                                                     *
 *  You should have received a copy of the GNU General Public License  *
 *  along with this program; if not, you can get it from:              *
 *  http://www.gnu.org/copyleft/gpl.html                               *
 ***********************************************************************/

#if HAVE_CONFIG_H
# include <config.h>
#endif

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h> /* div() */
#include <inttypes.h>

#include <sys/types.h>
#include <sys/time.h>
#include <time.h> /* gettimeofday() */
#include <sys/select.h> /* select() */
#include <sys/socket.h>
#include <unistd.h> /* close() */
#include <sys/ioctl.h>

#include <getopt.h>

#include <netdb.h> /* getaddrinfo() */
#include <arpa/inet.h> /* inet_ntop() */
#include <net/if.h> /* if_nametoindex() */

#include <netinet/icmp6.h>

static int fd;

static int
getipv6byname (const char *name, struct in6_addr *addr)
{
	struct addrinfo hints, *res;
	int val;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM; /* dummy */

	val = getaddrinfo (name, NULL, &hints, &res);
	if (val)
	{
		fprintf (stderr, "%s: %s\n", name, gai_strerror (val));
		return -1;
	}

	/* NOTE: we assume buffers have identical sizes */
	memcpy (addr, &((const struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
		sizeof (struct in6_addr));

	freeaddrinfo (res);
	return 0;
}


static int
getmacaddress (const char *ifname, uint8_t *addr)
{
	struct ifreq req;

	memset (&req, 0, sizeof (req));

	if (((unsigned)strlen (ifname)) >= (unsigned)IFNAMSIZ)
		return -1; /* buffer overflow = local root */
	strcpy (req.ifr_name, ifname);

	if (ioctl (fd, SIOCGIFHWADDR, &req))
	{
		perror (ifname);
		return -1;
	}

	memcpy (addr, req.ifr_hwaddr.sa_data, 6);
	return 0;
}


static int
setmcasthoplimit (int fd, int value)
{
	return setsockopt (fd, SOL_IPV6, IPV6_MULTICAST_HOPS,
				&value, sizeof (value));
}


static int
sendns (int fd, const struct in6_addr *tgt, const char *ifname)
{
	struct sockaddr_in6 addr;
	struct
	{
		struct nd_neighbor_solicit hdr;
		struct nd_opt_hdr opt;
		uint8_t hw_addr[6];
	} ns;

	/* determines multicast address */
	memset (&addr, 0, sizeof (addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_scope_id = if_nametoindex (ifname);
	memcpy (&addr.sin6_addr.s6_addr, "\xff\x02\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x01\xff", 13);
	memcpy (addr.sin6_addr.s6_addr + 13, tgt->s6_addr + 13,  3);

	/* builds ICMPv6 Neighbor Solicitation packet */
	ns.hdr.nd_ns_type = ND_NEIGHBOR_SOLICIT;
	ns.hdr.nd_ns_code = 0;
	ns.hdr.nd_ns_cksum = 0; /* computed by the kernel */
	ns.hdr.nd_ns_reserved = 0;
	memcpy (&ns.hdr.nd_ns_target, tgt, 16);

	ns.opt.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	ns.opt.nd_opt_len = 1; /* 8 bytes */

	/* gets our own interface's link-layer address (MAC) */
	if (getmacaddress (ifname, ns.hw_addr))
	{
		close (fd);
		return -1;
	}

	/* sets Hop-by-hop limit to 255 */
	setmcasthoplimit (fd, 255);

	if (sendto (fd, &ns, sizeof (ns), 0, (const struct sockaddr *)&addr,
			sizeof (addr)) != sizeof (ns))
	{
		perror ("Sending ICMPv6 neighbor solicitation");
		return -1;
	}

	return 0;
}


static int
recvna (int fd, struct in6_addr *tgt, unsigned wait_ms, int verbose)
{
	/* computes dead-line time */
	struct timeval end;

	gettimeofday (&end, NULL);
	{
		div_t d;
		
		d = div (wait_ms, 1000);
		end.tv_sec += d.quot;
		end.tv_usec += d.rem;
	}

	/* receive loop */
	while (1)
	{
		struct
		{
			struct nd_neighbor_advert na;
			uint8_t b[1500 - sizeof (struct nd_neighbor_advert)];
		} buf;
		struct sockaddr_in6 addr;
		fd_set set;
		int val;
		uint8_t *ptr;
		socklen_t len;
		struct timeval left, now;

		/* waits for reply for at most 3 seconds */
		FD_ZERO (&set);
		FD_SET (fd, &set);

		gettimeofday (&now, NULL);
		if (now.tv_sec > end.tv_sec
		 || (now.tv_sec == end.tv_sec
		  && now.tv_usec > end.tv_usec))
		{
			left.tv_sec = 0;
			left.tv_usec = 0;
		}
		else
		{
			left.tv_sec = end.tv_sec - now.tv_sec;
			left.tv_usec = end.tv_usec - now.tv_usec;

			if (end.tv_usec < now.tv_usec)
			{
				left.tv_sec --;
				left.tv_usec += 1000000;
			}
		}

		/* NOTE: Linux-like semantics assumed for select() */
		val = select (fd + 1, &set, NULL, NULL, &left);
		if (val < 0)
			return -1;

		if (val == 0)
			return 0;

		/* receives an ICMPv6 packet */
		len = sizeof (addr);
		val = recvfrom (fd, &buf, sizeof (buf), 0,
				(struct sockaddr *)&addr, &len);

		/* checks if the packet is a Neighbor Advertisement, and
		 * if the target IPv6 address is the right one */
		if ((val < sizeof (buf.na))
		 || (buf.na.nd_na_type != ND_NEIGHBOR_ADVERT)
		 || (buf.na.nd_na_code != 0)
		 || memcmp (&buf.na.nd_na_target, tgt, 16))
			continue;

		val -= sizeof (buf.na);

		/* looks for Target Link-layer address option */
		ptr = buf.b;

		while (val >= 8)
		{
			uint16_t optlen;

			optlen = ((uint16_t)(ptr[1])) << 3;
			if (optlen == 0)
				break; /* invalid length */

			val -= optlen;

			if (val < 0) /* length > remaining bytes */
				break;

			/* skips unrecognized option */
			if (ptr[0] != ND_OPT_TARGET_LINKADDR)
			{
				ptr += optlen;			
				continue;
			}

			/* Found! displays link-layer address */
			ptr += 2;
			if (verbose)
				fputs ("Target link-layer address: ", stdout);

			for (optlen -= 2; optlen > 1; optlen--)
			{
				printf ("%02X:", *ptr);
				ptr ++;
			}
			printf ("%02X\n", *ptr);

			if (verbose)
			{
				char str[INET6_ADDRSTRLEN];

				if (inet_ntop (AF_INET6, &addr.sin6_addr, str,
						sizeof (str)) != NULL)
					printf (" from %s\n", str);
			}

			return 1;
		}
	}

	return -1; /* dead code */
}


static int
ndisc (const char *name, const char *ifname, unsigned verbose, unsigned retry,
	unsigned wait_ms)
{
	struct in6_addr tgt;
	int i;

	fd = socket (PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (fd == -1)
	{
		perror ("ICMPv6 raw socket");
		return -1;
	}

	/* leaves root privileges if the program is setuid */
	setuid (getuid ());

	/* resolves target's IPv6 address */
	if (getipv6byname (name, &tgt))
	{
		close (fd);
		return -1;
	}
	else
	{
		char s[INET6_ADDRSTRLEN];

		inet_ntop (AF_INET6, &tgt, s, sizeof (s));
		if (verbose)
			printf ("Looking up %s (%s) on %s...\n", name, s,
				ifname);
	}

	for (i = 0; i < retry; i++)
	{
		int val;

		/* sends a Neigbor Solitication */
		if (sendns (fd, &tgt, ifname))
		{
			close (fd);
			return -1;
		}

		/* receives a Neighbor Advertisement */
		val = recvna (fd, &tgt, wait_ms, verbose);
		if (val > 0)
		{
			close (fd);
			return 0;
		}
		else
		if (val == 0)
		{
			if (verbose)
				puts ("Timed out.");
		}
		else
		{
			close (fd);
			perror ("Receiving ICMPv6 Neighbor Advertisement");
			return -1;
		}
	}

	close (fd);
	if (verbose)
		puts ("No response.");
	return -1;
}


static int
quick_usage (void)
{
	fputs ("Try \"ndisc -h\" for more information.\n", stderr);
	return 2;
}


static int
usage (void)
{
	fputs (
"Usage: ndisc [options] <IPv6 address> <interface>\n"
"Looks up an on-link IPv6 node link-layer address (Neighbor Discovery)\n"
"\n"
"  -h, --help     display this help and exit\n"
"  -q, --quiet    only print the link-layer address (useful for scripts)\n"
"  -r, --retry    number of attempts (default: 3)\n"
"  -V, --version  display program version and exit\n"
"  -v, --verbose  verbose display (this is the default)\n"
"  -w, --wait     how to long wait for a response [ms] (default: 1000)\n"
		"\n", stderr);
	return 0;
}


static int
version (void)
{
	puts (
"ndisc : IPv6 Neighbor Discovery userland tool $Rev$\n"
" built "__DATE__"\n"
"Copyright (C) 2004 Remi Denis-Courmont");
	puts (
"This is free software; see the source for copying conditions.\n"
"There is NO warranty; not even for MERCHANTABILITY or\n"
"FITNESS FOR A PARTICULAR PURPOSE.\n");
	printf ("Written by %s.\n", "Remi Denis-Courmont");
	return 0;
}



static struct option opts[] = 
{
	{ "help",	no_argument,		NULL, 'h' },
	{ "quiet",	no_argument,		NULL, 'q' },
	{ "retry",	required_argument,	NULL, 'r' },
	{ "version",	no_argument,		NULL, 'V' },
	{ "verbose",	no_argument,		NULL, 'v' },
	{ "wait",	required_argument,	NULL, 'w' }
};


int
main (int argc, char *argv[])
{
	int val;
	unsigned retry = 3, verbose = 1, wait_ms = 1000;
	const char *hostname, *ifname = NULL;

	while ((val = getopt_long (argc, argv, "hqr:Vw:", opts, NULL)) != EOF)
	{
		switch (val)
		{
			case 'h':
				return usage ();

			case 'q':
				verbose = 0;
				break;

			case 'r':
			{
				unsigned long l;
				char *end;

				l = strtoul (optarg, &end, 0);
				if (*end || l > UINT_MAX)
					return quick_usage ();
				retry = l;
				break;
			}
				
			case 'V':
				return version ();

			case 'v':
				if (verbose < UINT_MAX)
					verbose++;
				break;

			case 'w':
			{
				unsigned long l;
				char *end;

				l = strtoul (optarg, &end, 0);
				if (*end || l > UINT_MAX)
					return quick_usage ();
				wait_ms = l;
				break;
			}

			case '?':
			default:
				return quick_usage ();
		}
	}

	if (optind < argc)
		hostname = argv[optind++];
	if (optind < argc)
		ifname = argv[optind++];
	if ((optind < argc) || (ifname == NULL))
		return quick_usage ();

	return ndisc (hostname, ifname, verbose, retry, wait_ms) ? 1 : 0;
}

