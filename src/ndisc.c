/*
 * ndisc.c - ICMPv6 neighbour discovery command line tool
 * $Id$
 */

/***********************************************************************
 *  Copyright (C) 2004-2006 Rémi Denis-Courmont.                       *
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h> /* div() */
#include <inttypes.h>
#include <limits.h> /* UINT_MAX */

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

#include <netinet/in.h>
#include <netinet/icmp6.h>
#ifndef SOL_IPV6
# define SOL_IPV6 41 /* FreeBSD doesn't define this */
#endif

#ifndef RDISC
# define NAME "ndisc"
# define ND_TYPE_ADVERT ND_NEIGHBOR_ADVERT
# define TYPE_NAME "Neighbor"
# define NDISC_DEFAULT (NDISC_VERBOSE1 | NDISC_SINGLE)
#else
# define NAME "rdisc"
# define ND_TYPE_ADVERT ND_ROUTER_ADVERT
# define TYPE_NAME "Router"
# define NDISC_DEFAULT NDISC_VERBOSE1
#endif

static void drop_priv (void)
{
	/* leaves root privileges if setuid not run y root */
	setuid (getuid ());
}

enum ndisc_flags
{
	NDISC_VERBOSE1=0x1,
	NDISC_VERBOSE2=0x2,
	NDISC_VERBOSE3=0x3,
	NDISC_VERBOSE =0x3,
	NDISC_NUMERIC =0x4,
	NDISC_SINGLE  =0x8,
};

static int fd;

static int
getipv6byname (const char *name, const char *ifname, int numeric,
               struct sockaddr_in6 *addr)
{
	struct addrinfo hints, *res;
	int val;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM; /* dummy */
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;

	val = getaddrinfo (name, NULL, &hints, &res);
	if (val)
	{
		fprintf (stderr, _("%s: %s\n"), name, gai_strerror (val));
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

static void
printmacaddress (const uint8_t *ptr, size_t len)
{
	while (len > 1)
	{
		printf ("%02X:", *ptr);
		ptr++;
		len--;
	}

	if (len == 1)
		printf ("%02X\n", *ptr);
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

typedef struct
{
	struct nd_neighbor_solicit hdr;
	struct nd_opt_hdr opt;
	uint8_t hw_addr[6];
} solicit_packet;

static int
buildsol (solicit_packet *ns, struct sockaddr_in6 *tgt, const char *ifname)
{
	/* builds ICMPv6 Neighbor Solicitation packet */
	ns->hdr.nd_ns_type = ND_NEIGHBOR_SOLICIT;
	ns->hdr.nd_ns_code = 0;
	ns->hdr.nd_ns_cksum = 0; /* computed by the kernel */
	ns->hdr.nd_ns_reserved = 0;
	memcpy (&ns->hdr.nd_ns_target, &tgt->sin6_addr, 16);

	ns->opt.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	ns->opt.nd_opt_len = 1; /* 8 bytes */

	/* gets our own interface's link-layer address (MAC) */
	if (getmacaddress (ifname, ns->hw_addr))
		return -1;

	/* determines multicast address */
	memcpy (&tgt->sin6_addr.s6_addr, "\xff\x02\x00\x00\x00\x00\x00\x00"
	                                 "\x00\x00\x00\x01\xff", 13);

	return 0;
}


static int
parseadv (const uint8_t *buf, size_t len, const struct sockaddr_in6 *tgt,
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

		if (len < optlen) /* length > remaining bytes */
			break;
		len -= optlen;


		/* skips unrecognized option */
		if (ptr[0] != ND_OPT_TARGET_LINKADDR)
		{
			ptr += optlen;
			continue;
		}

		/* Found! displays link-layer address */
		ptr += 2;
		optlen -= 2;
		if (verbose)
			fputs (_("Target link-layer address: "), stdout);

		printmacaddress (ptr, optlen);
		return 0;
	}

	return -1;
}
#else
typedef struct nd_router_solicit solicit_packet;

static int
buildsol (solicit_packet *rs)
{
	/* builds ICMPv6 Router Solicitation packet */
	rs->nd_rs_type = ND_ROUTER_SOLICIT;
	rs->nd_rs_code = 0;
	rs->nd_rs_cksum = 0; /* computed by the kernel */
	rs->nd_rs_reserved = 0;
	return 0;
}


static int
parseprefix (const struct nd_opt_prefix_info *pi, size_t optlen, int verbose)
{
	char str[INET6_ADDRSTRLEN];

	if (optlen < sizeof (*pi))
		return -1;

	/* displays prefix informations */
	if (inet_ntop (AF_INET6, &pi->nd_opt_pi_prefix, str,
	               sizeof (str)) == NULL)
		return -1;

	if (verbose)
		fputs (_(" Prefix                   : "), stdout);
	printf ("%s/%u\n", str, pi->nd_opt_pi_prefix_len);

	if (verbose)
	{
		/* INET6_ADDRSTRLEN > 13 */
		unsigned v;

		fputs (_("  Valid time              : "), stdout);
		v = ntohl (pi->nd_opt_pi_valid_time);
		if (v == 0xffffffff)
			fputs (_("    infinite (0xffffffff)\n"), stdout);
		else
			printf (_("%12u (0x%08x) %s\n"),
			        v, v, ngettext ("second", "seconds", v));

		fputs (_("  Pref. time              : "), stdout);
		v = ntohl (pi->nd_opt_pi_preferred_time);
		if (v == 0xffffffff)
			fputs (_("    infinite (0xffffffff)\n"), stdout);
		else
			printf (_("%12u (0x%08x) %s\n"),
			        v, v, ngettext ("second", "seconds", v));
	}
	return 0;
}


static void
parsemtu (const struct nd_opt_mtu *m)
{
	unsigned mtu = ntohl (m->nd_opt_mtu_mtu);

	fputs (_(" MTU                      : "), stdout);
	printf ("       %5u %s (%s)\n", mtu,
	        ngettext ("byte", "bytes", mtu),
			gettext((mtu >= 1280) ? N_("valid") : N_("invalid")));
}


static int
parseadv (const uint8_t *buf, size_t len, int verbose)
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
		unsigned v;

		/* Hop limit */
		fputs (_("\n"
		         "Hop limit                 :    "), stdout);
		v = ra->nd_ra_curhoplimit;
		if (v != 0)
			printf (_("      %3u"), v);
		else
			fputs (_("undefined"), stdout);
		printf (_(" (      0x%02x)\n"), v);

		/* Router lifetime */
		fputs (_("Router lifetime           : "), stdout);
		v = ntohs (ra->nd_ra_router_lifetime);
		printf (_("%12u (0x%08x) %s\n"), v, v,
		        ngettext ("millisecond", "milliseconds", v));

		/* ND Reachable time */
		fputs (_("Reachable time            : "), stdout);
		v = ntohl (ra->nd_ra_reachable);
		if (v != 0)
			printf (_("%12u (0x%08x) %s\n"), v, v,
			        ngettext ("millisecond", "milliseconds", v));
		else
			fputs (_(" unspecified (0x00000000)\n"), stdout);

		/* ND Retransmit time */
		fputs (_("Retransmit time           : "), stdout);
		v = ntohl (ra->nd_ra_retransmit);
		if (v != 0)
			printf (_("%12u (0x%08x) %s\n"), v, v,
			        ngettext ("millisecond", "milliseconds", v));
		else
			fputs (_(" unspecified (0x00000000)\n"), stdout);
	}
	len -= sizeof (struct nd_router_advert);

	/* parses options */
	ptr = buf + sizeof (struct nd_router_advert);

	while (len >= 8)
	{
		uint16_t optlen;

		optlen = ((uint16_t)(ptr[1])) << 3;
		if ((optlen == 0) /* invalid length */
		 || (len < optlen) /* length > remaining bytes */)
			break;

		len -= optlen;

		/* skips unrecognized option */
		switch (ptr[0])
		{
			case ND_OPT_SOURCE_LINKADDR:
				if (verbose)
				{
					fputs (" Source link-layer address: ", stdout);
					printmacaddress (ptr + 2, optlen - 2);
				}
				break;

			case ND_OPT_TARGET_LINKADDR:
				break; /* ignore */

			case ND_OPT_PREFIX_INFORMATION:
				if (parseprefix ((const struct nd_opt_prefix_info *)ptr,
				                 optlen, verbose))
					return -1;

			case ND_OPT_REDIRECTED_HEADER:
				break; /* ignore */

			case ND_OPT_MTU:
				if (verbose)
					parsemtu ((const struct nd_opt_mtu *)ptr);
				break;
		}

		ptr += optlen;
	}

	return 0;
}

# define buildsol( a, b, c ) buildsol (a)
# define parseadv( a, b, c, d ) parseadv (a, b, d)
#endif

static int
recvadv (int fd, const struct sockaddr_in6 *tgt, unsigned wait_ms,
         unsigned flags)
{
	struct timeval now, end;
	unsigned responses = 0;

	gettimeofday (&now, NULL);
	/* computes deadline time */
	{
		div_t d;
		
		d = div (wait_ms, 1000);
		end.tv_sec = now.tv_sec + d.quot;
		end.tv_usec = now.tv_usec + d.rem;
	}

	/* receive loop */
	for (;;)
	{
		uint8_t buf[1500]; /* TODO: use interface MTU */
		struct sockaddr_in6 addr;
		fd_set set;
		struct timeval left;
		int val;

		/* waits for reply until deadline */
		FD_ZERO (&set);
		FD_SET (fd, &set);

		if ((now.tv_sec < end.tv_sec)
		 || ((now.tv_sec == end.tv_sec) && (now.tv_usec <= end.tv_usec)))
		{
			left.tv_sec = end.tv_sec - now.tv_sec;
			left.tv_usec = end.tv_usec - now.tv_usec;

			if (end.tv_usec < now.tv_usec)
			{
				/* carry */
				left.tv_sec --;
				left.tv_usec += 1000000;
			}
		}
		else
		{
			/* time is UP: reads already queued packets and exit */
			left.tv_sec = 0;
			left.tv_usec = 0;
		}

		val = select (fd + 1, &set, NULL, NULL, &left);
		if (val < 0)
			break;

		if (val == 0)
			return responses;
		else
		{
			/* receives an ICMPv6 packet */
			socklen_t len = sizeof (addr);

			/* TODO: ensure packet TTL is 255 (if possible) */
			val = recvfrom (fd, &buf, sizeof (buf), MSG_DONTWAIT,
					(struct sockaddr *)&addr, &len);
			if (val < 0)
			{
				perror (_("Receiving ICMPv6 packet"));
				continue;
			}
		}

		/* ensures the response came through the right interface */
		if (addr.sin6_scope_id
		 && (addr.sin6_scope_id != tgt->sin6_scope_id))
			continue;

		if (parseadv (buf, val, tgt, flags & NDISC_VERBOSE) == 0)
		{
			if (flags & NDISC_VERBOSE)
			{
				char str[INET6_ADDRSTRLEN];

				if (inet_ntop (AF_INET6, &addr.sin6_addr, str,
						sizeof (str)) != NULL)
					printf (_(" from %s\n"), str);
			}

			if (responses < INT_MAX)
				responses++;

			if (flags & NDISC_SINGLE)
				return 1 /* = responses */;
		}
		gettimeofday (&now, NULL);
	}

	return -1; /* error */
}


static int
ndisc (const char *name, const char *ifname, unsigned flags, unsigned retry,
       unsigned wait_ms)
{
	struct sockaddr_in6 tgt;

	fd = socket (PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (fd == -1)
	{
		perror (_("ICMPv6 raw socket"));
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
	if (getipv6byname (name, ifname, (flags & NDISC_NUMERIC) ? 1 : 0, &tgt))
		goto error;
	else
	{
		char s[INET6_ADDRSTRLEN];

		inet_ntop (AF_INET6, &tgt.sin6_addr, s, sizeof (s));
		if (flags & NDISC_VERBOSE)
			printf (_("Soliciting %s (%s) on %s...\n"), name, s, ifname);
	}

	{
		solicit_packet packet;
		struct sockaddr_in6 dst;

		memcpy (&dst, &tgt, sizeof (dst));
		if (buildsol (&packet, &dst, ifname))
			goto error;

		while (retry > 0)
		{
			int val;
	
			/* sends a Solitication */
			if (sendto (fd, &packet, sizeof (packet), MSG_DONTROUTE,
			            (const struct sockaddr *)&dst,
			            sizeof (dst)) != sizeof (packet))
			{
				perror (_("Sending ICMPv6 packet"));
				goto error;
			}
			retry--;
	
			/* receives an Advertisement */
			val = recvadv (fd, &tgt, wait_ms, flags);
			if (val > 0)
			{
				close (fd);
				return 0;
			}
			else
			if (val == 0)
			{
				if (flags & NDISC_VERBOSE)
					puts (_("Timed out."));
			}
			else
				goto error;
		}
	}

	close (fd);
	if (flags & NDISC_VERBOSE)
		puts (_("No response."));
	return -2;

error:
	close (fd);
	return -1;
}


static int
quick_usage (const char *path)
{
	drop_priv ();

	fprintf (stderr, _("Try \"%s -h\" for more information.\n"), path);
	return 2;
}


static int
usage (const char *path)
{
	drop_priv ();

	fprintf (stderr,
#ifndef RDISC
_("Usage: %s [options] <IPv6 address> <interface>\n"
"Looks up an on-link IPv6 node link-layer address (Neighbor Discovery)\n")
#else
_("Usage: %s [options] [IPv6 address] <interface>\n"
"Solicits on-link IPv6 routers (Router Discovery)\n")
#endif
		, path);

	fprintf (stderr, _("\n"
"  -1, --single   display first response and exit\n"
"  -h, --help     display this help and exit\n"
"  -m, --multiple wait and display all responses\n"
"  -n, --numeric  don't resolve host names\n"
"  -q, --quiet    only print the %s (mainly for scripts)\n"
"  -r, --retry    maximum number of attempts (default: 3)\n"
"  -V, --version  display program version and exit\n"
"  -v, --verbose  verbose display (this is the default)\n"
"  -w, --wait     how long to wait for a response [ms] (default: 1000)\n"
	           "\n"),
#ifndef RDISC
	           _("link-layer address")
#else
	           _("advertised prefixes")
#endif
		);

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
	puts (_(
"This is free software; see the source for copying conditions.\n"
"There is NO warranty; not even for MERCHANTABILITY or\n"
"FITNESS FOR A PARTICULAR PURPOSE.\n"));
	printf (_("Written by %s.\n"), "Remi Denis-Courmont");
	return 0;
}



static struct option opts[] = 
{
	{ "single",   no_argument,       NULL, '1' },
	{ "help",     no_argument,       NULL, 'h' },
	{ "multiple", required_argument, NULL, 'm' },
	{ "numeric",  no_argument,       NULL, 'n' },
	{ "quiet",    no_argument,       NULL, 'q' },
	{ "retry",    required_argument, NULL, 'r' },
	{ "version",  no_argument,       NULL, 'V' },
	{ "verbose",  no_argument,       NULL, 'v' },
	{ "wait",     required_argument, NULL, 'w' }
};


int
main (int argc, char *argv[])
{
	int val;
	unsigned retry = 3, flags = NDISC_DEFAULT, wait_ms = 1000;
	const char *hostname, *ifname;

	while ((val = getopt_long (argc, argv, "1hmnqr:Vvw:", opts, NULL)) != EOF)
	{
		switch (val)
		{
			case '1':
				flags |= NDISC_SINGLE;
				break;

			case 'h':
				return usage (argv[0]);

			case 'm':
				flags &= ~NDISC_SINGLE;
				break;

			case 'n':
				flags |= NDISC_NUMERIC;
				break;

			case 'q':
				flags &= ~NDISC_VERBOSE;
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
				/* NOTE: assume NDISC_VERBOSE occupies low-order bits */
				if ((flags & NDISC_VERBOSE) < NDISC_VERBOSE)
					flags++;
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

	return -ndisc (hostname, ifname, flags, retry, wait_ms);
}

