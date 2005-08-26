/*
 * ndisc.c - ICMPv6 neighbour discovery command line tool
 * $Id$
 */

/***********************************************************************
 *  Copyright (C) 2004-2005 Remi Denis-Courmont.                       *
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

#ifndef RDISC
# define NAME "ndisc"
# define ND_TYPE_ADVERT ND_NEIGHBOR_ADVERT
# define TYPE_NAME "Neighbor"
#else
# define NAME "rdisc"
# define ND_TYPE_ADVERT ND_ROUTER_ADVERT
# define TYPE_NAME "Router"
#endif

static void drop_priv (void)
{
	/* leaves root privileges if setuid not run y root */
	setuid (getuid ());
}

static int fd;

static int
getipv6byname (const char *name, const char *ifname,
               struct sockaddr_in6 *addr)
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

	memcpy (addr, res->ai_addr, sizeof (struct sockaddr_in6));
	freeaddrinfo (res);

	val = if_nametoindex (ifname);
	if (val == 0)
	{
		perror (ifname);
		return -1;
	}
	addr->sin6_scope_id = val;

	return 0;
}


static int
setmcasthoplimit (int fd, int value)
{
	return setsockopt (fd, SOL_IPV6, IPV6_MULTICAST_HOPS,
				&value, sizeof (value));
}


#ifndef RDISC
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
sendns (int fd, const struct sockaddr_in6 *tgt, const char *ifname)
{
	struct sockaddr_in6 addr;
	struct
	{
		struct nd_neighbor_solicit hdr;
		struct nd_opt_hdr opt;
		uint8_t hw_addr[6];
	} ns;

	/* determines multicast address */
	memcpy (&addr, tgt, sizeof (addr));
	memcpy (&addr.sin6_addr.s6_addr, "\xff\x02\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x01\xff", 13);

	/* builds ICMPv6 Neighbor Solicitation packet */
	ns.hdr.nd_ns_type = ND_NEIGHBOR_SOLICIT;
	ns.hdr.nd_ns_code = 0;
	ns.hdr.nd_ns_cksum = 0; /* computed by the kernel */
	ns.hdr.nd_ns_reserved = 0;
	memcpy (&ns.hdr.nd_ns_target, &tgt->sin6_addr, 16);

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
parsena (const uint8_t *buf, size_t len, const struct sockaddr_in6 *tgt,
         int verbose)
{
	const struct nd_neighbor_advert *na =
		(const struct nd_neighbor_advert *)buf;
	const uint8_t *ptr;
	
	/* checks if the packet is a Neighbor Advertisement, and
	 * if the target IPv6 address is the right one */
	if ((len < sizeof (struct nd_neighbor_advert))
	 || (na->nd_na_type != ND_NEIGHBOR_ADVERT)
	 || (na->nd_na_code != 0)
	 || memcmp (&na->nd_na_target, &tgt->sin6_addr, 16))
		return -1;

	len -= sizeof (struct nd_neighbor_advert);

	/* looks for Target Link-layer address option */
	ptr = buf + sizeof (struct nd_neighbor_advert);

	while (len >= 8)
	{
		uint16_t optlen;

		optlen = ((uint16_t)(ptr[1])) << 3;
		if (optlen == 0)
			break; /* invalid length */

		len -= optlen;

		if (len < 0) /* length > remaining bytes */
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

		return 0;
	}

	return -1;
}
#else
static int
sendrs (int fd, const struct sockaddr_in6 *tgt)
{
	struct nd_router_solicit rs;

	/* builds ICMPv6 Neighbor Solicitation packet */
	rs.nd_rs_type = ND_ROUTER_SOLICIT;
	rs.nd_rs_code = 0;
	rs.nd_rs_cksum = 0; /* computed by the kernel */
	rs.nd_rs_reserved = 0;

	if (sendto (fd, &rs, sizeof (rs), 0, (const struct sockaddr *)tgt,
	            sizeof (struct sockaddr_in6)) != sizeof (rs))
	{
		perror ("Sending ICMPv6 neighbor solicitation");
		return -1;
	}

	return 0;
}


static int
parsera (const uint8_t *buf, size_t len, int verbose)
{
	const struct nd_router_advert *ra =
		(const struct nd_router_advert *)buf;
	const uint8_t *ptr;
	
	/* checks if the packet is a Router Advertisement */
	if ((len < sizeof (struct nd_router_advert))
	 || (ra->nd_ra_type != ND_ROUTER_ADVERT)
	 || (ra->nd_ra_code != 0))
		return -1;

	if (verbose)
	{
		printf ("\n"
			"Hop limit      :          %3u (      0x%02x)\n"
			"Router lifetime: %12u (0x%08x) second(s)\n"
			"Reachable time : %12u (0x%08x) second(s)\n"
			"Retrans. time  : %12u (0x%08x) second(s)\n",
			(unsigned)ra->nd_ra_curhoplimit,
			(unsigned)ra->nd_ra_curhoplimit,
			(unsigned)ntohl (ra->nd_ra_router_lifetime),
			(unsigned)ntohl (ra->nd_ra_router_lifetime),
			(unsigned)ntohl (ra->nd_ra_reachable),
			(unsigned)ntohl (ra->nd_ra_reachable),
			(unsigned)ntohl (ra->nd_ra_retransmit),
			(unsigned)ntohl (ra->nd_ra_retransmit));
	}
	len -= sizeof (struct nd_router_advert);

	/* looks for Target Link-layer address option */
	ptr = buf + sizeof (struct nd_router_advert);

	while (len >= 8)
	{
		uint16_t optlen;
		char str[INET6_ADDRSTRLEN];

		optlen = ((uint16_t)(ptr[1])) << 3;
		if (optlen == 0)
			break; /* invalid length */

		len -= optlen;

		if (len < 0) /* length > remaining bytes */
			break;

		/* skips unrecognized option */
		/* FIXME: support for other option!! */
		if (ptr[0] != ND_OPT_PREFIX_INFORMATION)
		{
			ptr += optlen;
			continue;
		}

		const struct nd_opt_prefix_info *pi =
			(const struct nd_opt_prefix_info *)ptr;

		/* displays prefix informations */
		if (inet_ntop (AF_INET6, &pi->nd_opt_pi_prefix, str,
				sizeof (str)) == NULL)
			return -1;

		if (verbose)
			fputs (" Prefix        : ", stdout);
		printf ("%s/%u\n", str, pi->nd_opt_pi_prefix_len);
		if (verbose)
			printf ("  Valid time   : %12u (0x%08x) second(s)\n"
				"  Pref. time   : %12u (0x%08x) second(s)\n"
				,
				(unsigned)ntohl (pi->nd_opt_pi_valid_time),
				(unsigned)ntohl (pi->nd_opt_pi_valid_time),
				(unsigned)ntohl(pi->nd_opt_pi_preferred_time),
				(unsigned)ntohl (pi->nd_opt_pi_preferred_time)
				);

		ptr += optlen;
	}

	return 0;
}
# define sendns( a, b, c ) sendrs (a, b)
# define parsena( a, b, c, d ) parsera (a, b, d)
#endif


static int
recvpayload (int fd, const struct sockaddr_in6 *tgt, unsigned wait_ms,
             int verbose)
{
	/* computes dead-line time */
	struct timeval end;
	int responses = 0;

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
		uint8_t buf[1500];
		struct sockaddr_in6 addr;
		fd_set set;
		int val;
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

		val = select (fd + 1, &set, NULL, NULL, &left);
		if (val < 0)
			return -1;

		if (val == 0)
			return responses ? 1 : 0;
		else
		{
			/* receives an ICMPv6 packet */
			socklen_t len = sizeof (addr);

			val = recvfrom (fd, &buf, sizeof (buf), 0,
					(struct sockaddr *)&addr, &len);
			if (val < 0)
			{
				perror ("recvfrom failed");
				continue;
			}
		}

		/* ensures the response came through the right interface */
		if (addr.sin6_scope_id
		 && (addr.sin6_scope_id != tgt->sin6_scope_id))
			continue;

		if (parsena (buf, val, tgt, verbose) == 0)
		{
			if (verbose)
			{
				char str[INET6_ADDRSTRLEN];

				if (inet_ntop (AF_INET6, &addr.sin6_addr, str,
						sizeof (str)) != NULL)
					printf (" from %s\n", str);
			}

			responses++;
#ifndef RDISC
			/* TODO: option to show duplicate responses
			 * with ndisc */
			return 1;
#endif
		}
	}

	return -1; /* dead code */
}


static int
ndisc (const char *name, const char *ifname, unsigned verbose, unsigned retry,
       unsigned wait_ms)
{
	struct sockaddr_in6 tgt;

	fd = socket (PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (fd == -1)
	{
		perror ("ICMPv6 raw socket");
		return -1;
	}

	drop_priv ();

	/* set ICMPv6 filter */
	{
		struct icmp6_filter f;

		ICMP6_FILTER_SETBLOCKALL (&f);
		ICMP6_FILTER_SETPASS (ND_TYPE_ADVERT, &f);
		setsockopt (fd, IPPROTO_ICMPV6, ICMP6_FILTER, &f, sizeof (f));
	}

	/* sets Hop-by-hop limit to 255 */
	setmcasthoplimit (fd, 255);

	/* resolves target's IPv6 address */
	if (getipv6byname (name, ifname, &tgt))
	{
		close (fd);
		return -1;
	}

	{
		char s[INET6_ADDRSTRLEN];

		inet_ntop (AF_INET6, &tgt.sin6_addr, s, sizeof (s));
		if (verbose)
			printf ("Soliciting %s (%s) on %s...\n", name, s,
				ifname);
	}

	while (retry > 0)
	{
		int val;

		/* sends a Neigbor Solitication */
		if (sendns (fd, &tgt, ifname))
		{
			close (fd);
			return -1;
		}
		retry--;

		/* receives a Neighbor Advertisement */
		val = recvpayload (fd, &tgt, wait_ms, verbose);
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
			perror ("Receiving ICMPv6 "TYPE_NAME" Advertisement");
			return -1;
		}
	}

	close (fd);
	if (verbose)
		puts ("No response.");
	return -2;
}


static int
quick_usage (const char *path)
{
	drop_priv ();

	fprintf (stderr, "Try \"%s -h\" for more information.\n", path);
	return 2;
}


static int
usage (const char *path)
{
	drop_priv ();

	fprintf (stderr,
#ifndef RDISC
"Usage: %s [options] <IPv6 address> <interface>\n"
"Looks up an on-link IPv6 node link-layer address (Neighbor Discovery)\n"
#else
"Usage: %s [options] [IPv6 address] <interface>\n"
"Solicits on-link IPv6 routers (Router Discovery)\n"
#endif
"\n"
"  -h, --help     display this help and exit\n"
#ifndef RDISC
"  -q, --quiet    only print the link-layer address (useful for scripts)\n"
#else
"  -q, --quiet    only print the advertised prefixes (useful for scripts)\n"
#endif
"  -r, --retry    number of attempts (default: 3)\n"
"  -V, --version  display program version and exit\n"
"  -v, --verbose  verbose display (this is the default)\n"
"  -w, --wait     how to long wait for a response [ms] (default: 1000)\n"
		"\n", path);
	return 0;
}


static int
version (void)
{
	drop_priv ();

	puts (
NAME"6 : IPv6 "TYPE_NAME" Discovery userland tool "PACKAGE_VERSION
" ($Rev$)\n built "__DATE__"\n"
"Copyright (C) 2004-2005 Remi Denis-Courmont");
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
	const char *hostname, *ifname;

	while ((val = getopt_long (argc, argv, "hqr:Vvw:", opts, NULL)) != EOF)
	{
		switch (val)
		{
			case 'h':
				return usage (argv[0]);

			case 'q':
				verbose = 0;
				break;

			case 'r':
			{
				unsigned long l;
				char *end;

				l = strtoul (optarg, &end, 0);
				if (*end || l > UINT_MAX)
					return quick_usage (argv[0]);
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
					return quick_usage (argv[0]);
				wait_ms = l;
				break;
			}

			case '?':
			default:
				return quick_usage (argv[0]);
		}
	}

	if (optind < argc)
	{
		hostname = argv[optind++];

		if (optind < argc)
			ifname = argv[optind++];
		else
			ifname = NULL;
	}
	else
		return quick_usage (argv[0]);

#ifdef RDISC
	if (ifname == NULL)
	{
		ifname = hostname;
		hostname = "ff02::2";
	}
	else
#endif
	if ((optind != argc) || (ifname == NULL))
		return quick_usage (argv[0]);

	return -ndisc (hostname, ifname, verbose, retry, wait_ms);
}

