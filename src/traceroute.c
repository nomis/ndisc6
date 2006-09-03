/*
 * traceroute.c - TCP/IPv6 traceroute tool
 * $Id$
 */

/***********************************************************************
 *  Copyright (C) 2005-2006 Rémi Denis-Courmont.                       *
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h> /* div() */
#include <limits.h>
#include <stdbool.h>
#include <time.h> /* nanosleep() */

#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>
#include <net/if.h> // IFNAMSIZ
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netdb.h>
#include <arpa/inet.h> /* inet_ntop() */
#include <fcntl.h>
#include <errno.h>
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif
#include "gettime.h"
#ifndef SOL_IPV6
# define SOL_IPV6 IPPROTO_IPV6
#endif
#ifndef SOL_ICMPV6
# define SOL_ICMPV6 IPPROTO_ICMPV6
#endif

#include "traceroute.h"


/* All our evil global variables */
static const tracetype *type = NULL;
static int niflags = 0;
static int sendflags = 0;
static int tclass = -1;
uint16_t sport;
static bool debug = false;
bool ecn = false;
static char ifname[IFNAMSIZ] = "";


/****************************************************************************/

static void
drop_priv (void)
{
	setuid (getuid ());
}


static uint16_t getsourceport (void)
{
	uint16_t v = ~getpid ();
	if (v < 1025)
		v += 1025;
	return htons (v);
}


int send_payload (int fd, const void *payload, size_t length)
{
	int rc = send (fd, payload, length, sendflags);

	if (rc == (int)length)
		return 0;

	if (rc != -1)
		errno = EMSGSIZE;
	return -1;
}


static bool has_port (int protocol)
{
	switch (protocol)
	{
		case IPPROTO_UDP:
		case IPPROTO_TCP:
		//case IPPROTO_SCTP:
		//case IPPROTO_DCCP:
			return true;
	}
	return false;
}


/* Performs reverse lookup; print hostname and address */
static void
printname (const struct sockaddr *addr, size_t addrlen)
{
	char buf[NI_MAXHOST];

	if (getnameinfo (addr, addrlen, buf, sizeof (buf), NULL, 0, niflags))
		return;
	printf (" %s", buf);

	if (getnameinfo (addr, addrlen, buf, sizeof (buf), NULL, 0,
	                 NI_NUMERICHOST | niflags))
		return;
	printf (" (%s) ", buf);
}


static inline void
printipv6 (const struct sockaddr_in6 *addr)
{
	printname ((const struct sockaddr *)addr, sizeof (*addr));
}


/* Prints delay between two dates */
static void
printdelay (const struct timespec *from, const struct timespec *to)
{
	div_t d = div ((to->tv_nsec - from->tv_nsec) / 1000, 1000);

	/*
	 * For some stupid reasons, div() returns a negative remainder when
	 * the numerator is negative, instead of following the mathematician
	 * convention that the remainder always be positive.
	 */
	if (d.rem < 0)
	{
		d.quot--;
		d.rem += 1000;
        }
	d.quot += 1000 * (to->tv_sec - from->tv_sec);

	printf (_(" %u.%03u ms "), (unsigned)(d.quot), (unsigned)d.rem);
}


static void
print_icmp_code (const struct icmp6_hdr *hdr)
{
	if (hdr->icmp6_type == ICMP6_DST_UNREACH)
	{
		/* No path to destination */
		char c = '\0';

		switch (hdr->icmp6_code)
		{
			case ICMP6_DST_UNREACH_NOROUTE:
				c = 'N';
				break;

			case ICMP6_DST_UNREACH_ADMIN:
				c = 'S';
				break;

			case ICMP6_DST_UNREACH_ADDR:
				c = 'H';
				break;

			case ICMP6_DST_UNREACH_NOPORT:
				break;
		}

		if (c)
			printf ("!%c ", c);
	}
}


static int
probe_ttl (int protofd, int icmpfd, const struct sockaddr_in6 *dst,
           unsigned ttl, unsigned retries, unsigned timeout, unsigned delay,
           size_t plen)
{
	struct in6_addr hop; /* hop if known from previous probes */
	unsigned n;
	int found = 0;
	int state = -1; /* type of response received so far (-1: none,
		0: normal, 1: closed, 2: open) */
	/* see also: found (0: not found, <0: unreachable, >0: reached) */
	struct timespec delay_ts;
	{
		div_t d = div (delay, 1000);
		delay_ts.tv_sec = d.quot;
		delay_ts.tv_nsec = d.rem * 1000000;
	}

	memset (&hop, 0, sizeof (hop));
	printf ("%2d ", ttl);
	setsockopt (protofd, SOL_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof (ttl));

	for (n = 0; n < retries; n++)
	{
		struct timespec sent, recvd;

		gettime (&sent);
		if (type->send_probe (protofd, ttl, n, plen, dst->sin6_port))
		{
			perror (_("Cannot send packet"));
			return -1;
		}

		for (;;)
		{
			struct pollfd ufds[2];

			memset (ufds, 0, sizeof (ufds));
			ufds[0].fd = protofd;
			ufds[0].events = POLLIN;
			ufds[1].fd = icmpfd;
			ufds[1].events = POLLIN;

			gettime (&recvd);
			int val = ((sent.tv_sec + timeout - recvd.tv_sec) * 1000)
				+ (int)((sent.tv_nsec - recvd.tv_nsec) / 1000000);

			val = poll (ufds, 2, val > 0 ? val : 0);
			if (val < 0) /* interrupted by signal - well, not really */
				return -1;

			if (val == 0)
			{
				fputs (" *", stdout);
				break;
			}

			gettime (&recvd);

			/* Receive final packet when host reached */
			if (ufds[0].revents)
			{
				uint8_t buf[1240];

				int len = recv (protofd, buf, sizeof (buf), 0);
				if (len < 0)
				{
					switch (errno)
					{
#ifdef EPROTO
						case EPROTO:
							/* Parameter problem seemingly can't be read from
							 * the ICMPv6 socket, regardless of the filter. */
							break;
#endif

						case EAGAIN:
						case ECONNREFUSED:
							continue;

						default:
							/* These are very bad errors (-> bugs) */
							perror (_("Receive error"));
							return -1;
					}

					if (state == -1)
					{
						printipv6 (dst);
						state = 1;
						found = ttl;
					}
					printdelay (&sent, &recvd);
					break;
				}

				if (type->parse_resp == NULL)
					continue;

				unsigned pttl, pn;
				len = type->parse_resp (buf, len, &pttl, &pn, dst->sin6_port);
				if ((len >= 0) && (n == pn) && (pttl = ttl))
				{
					/* Route determination complete! */
					if (state == -1)
						printipv6 (dst);

					if (len != state)
					{
						const char *msg = NULL;

						switch (len)
						{
							case 1:
								msg = N_("closed");
								break;

							case 2:
								msg = N_("open");
								break;
						}

						if (msg != NULL)
							printf ("[%s] ", msg);

						state = len;
					}

					printdelay (&sent, &recvd);
					found = ttl;
					break;
				}
			}

			/* Receive ICMP errors along the way */
			if (ufds[1].revents)
			{
				struct
				{
					struct icmp6_hdr hdr;
					struct ip6_hdr inhdr;
					uint8_t buf[1192];
				} pkt;
				struct sockaddr_in6 peer;

				int len = recvfrom (icmpfd, &pkt, sizeof (pkt), 0,
				                    (struct sockaddr *)&peer,
				                    &(socklen_t){ sizeof (peer) });

				if (len < (int)(sizeof (pkt.hdr) + sizeof (pkt.inhdr)))
					continue; // too small

				switch (pkt.hdr.icmp6_type)
				{
					case ICMP6_DST_UNREACH:
						if (found == 0)
						{
							switch (pkt.hdr.icmp6_code)
							{
								case ICMP6_DST_UNREACH_NOPORT:
									found = ttl;
									break;

								default:
									found = -ttl;
							}
						}
						break;

					case ICMP6_TIME_EXCEEDED:
						if (pkt.hdr.icmp6_code == ICMP6_TIME_EXCEED_TRANSIT)
							break;

					default: // should not happen (ICMPv6 filter)
						continue;
				}

				if (memcmp (&pkt.inhdr.ip6_dst, &dst->sin6_addr, 16))
					continue; // wrong destination

				if (pkt.inhdr.ip6_nxt != type->protocol)
					continue; // wrong protocol

				len -= sizeof (pkt.hdr) + sizeof (pkt.inhdr);

				unsigned pttl, pn;
				len = type->parse_err (pkt.buf, len, &pttl, &pn,
				                       dst->sin6_port);
				if ((len < 0) || (pttl != ttl)
				 || ((pn != n) && (pn != (unsigned)(-1))))
					continue;

				/* genuine ICMPv6 error that concerns us */
				if ((state == -1) || memcmp (&hop, &peer.sin6_addr, 16))
				{
					memcpy (&hop, &peer.sin6_addr, 16);
					printipv6 (&peer);
					state = 0;
				}

				printdelay (&sent, &recvd);
				print_icmp_code (&pkt.hdr);
				break;
			}
		}

		if (delay)
			clock_nanosleep (CLOCK_MONOTONIC, 0, &delay_ts, NULL);
	}
	puts ("");
	return found;
}


static int
getaddrinfo_err (const char *host, const char *serv,
                 const struct addrinfo *hints, struct addrinfo **res)
{
	int val = getaddrinfo (host, serv, hints, res);
	if (val)
	{
		fprintf (stderr, _("%s%s%s%s: %s\n"), host ?: "", host ? " " : "",
		         serv ? _("port ") : "", serv ?: "", gai_strerror (val));
		return val;
	}
	return 0;
}


static int
connect_proto (int fd, struct sockaddr_in6 *dst,
               const char *dsthost, const char *dstport,
               const char *srchost, const char *srcport)
{
	struct addrinfo hints, *res;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = type->gai_socktype;

	if ((srchost != NULL) || (srcport != NULL))
	{
		hints.ai_flags |= AI_PASSIVE;

		if (getaddrinfo_err (srchost, srcport, &hints, &res))
			return -1;

		if (bind (fd, res->ai_addr, res->ai_addrlen))
		{
			perror (srchost);
			goto error;
		}

		if (srcport != NULL)
			sport = ((const struct sockaddr_in6 *)res->ai_addr)->sin6_port;
		freeaddrinfo (res);

		hints.ai_flags &= ~AI_PASSIVE;
	}

	if (srcport == NULL)
		sport = getsourceport ();

	if (getaddrinfo_err (dsthost, dstport, &hints, &res))
		return -1;

	if (res->ai_addrlen > sizeof (*dst))
		goto error;

	if (connect (fd, res->ai_addr, res->ai_addrlen))
	{
		perror (dsthost);
		goto error;
	}

	char buf[INET6_ADDRSTRLEN];
	fputs (_("traceroute to"), stdout);
	printname (res->ai_addr, res->ai_addrlen);

	if ((getsockname (fd, (struct sockaddr *)dst,
	                  &(socklen_t){ sizeof (*dst) }) == 0)
	 && inet_ntop (AF_INET6, &dst->sin6_addr, buf, sizeof (buf)))
		printf (_("from %s, "), buf);

	memcpy (dst, res->ai_addr, res->ai_addrlen);
	if (has_port (type->protocol))
	{
		printf (_("port %u, "), ntohs (dst->sin6_port));
		printf (_("from port %u, "), ntohs (sport));
	}

	freeaddrinfo (res);
	return 0;

error:
	freeaddrinfo (res);
	return -1;
}


static void setup_socket (int fd)
{
	if (debug)
		setsockopt (fd, SOL_SOCKET, SO_DEBUG, &(int) { 1 }, sizeof (int));
	setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &(int) { 1 }, sizeof (int));

	int val = fcntl (fd, F_GETFL);
	if (val == -1)
		val = 0;
	fcntl (fd, F_SETFL, O_NONBLOCK | val);
	fcntl (fd, F_GETFD, FD_CLOEXEC);
}


static int
traceroute (const char *dsthost, const char *dstport,
            const char *srchost, const char *srcport,
            unsigned timeout, unsigned delay, unsigned retries,
            size_t packet_len, unsigned min_ttl, unsigned max_ttl)
{
	struct sockaddr_in6 dst;
	int protofd, icmpfd, val;
	unsigned ttl;

	/* Creates ICMPv6 socket to collect error packets */
	icmpfd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (icmpfd == -1)
	{
		perror (_("Raw IPv6 socket"));
		return -1;
	}

	/* Creates protocol-specific socket */
	protofd = socket (AF_INET6, SOCK_RAW, type->protocol);
	if (protofd == -1)
	{
		perror (_("Raw IPv6 socket"));
		close (icmpfd);
		return -1;
	}

#ifdef SO_BINDTODEVICE
	if (*ifname
	 && setsockopt (protofd, SOL_SOCKET, SO_BINDTODEVICE, ifname,
	                strlen (ifname) + 1))
	{
		perror (ifname);
		close (protofd);
		close (icmpfd);
		return -1;
	}
	/* FIXME: implement on non-Linux */
#endif

	/* Drops privileges permanently */
	drop_priv ();

	if (icmpfd <= 2)
	{
		close (icmpfd);
		close (protofd);
		return -1;
	}

	setup_socket (icmpfd);
	setup_socket (protofd);

	/* Set ICMPv6 filter */
	{
		struct icmp6_filter f;

		ICMP6_FILTER_SETBLOCKALL (&f);
		ICMP6_FILTER_SETPASS (ICMP6_DST_UNREACH, &f);
		ICMP6_FILTER_SETPASS (ICMP6_TIME_EXCEEDED, &f);
		setsockopt (icmpfd, SOL_ICMPV6, ICMP6_FILTER, &f, sizeof (f));
	}

	/* Defines protocol-specific checksum offset */
	if ((type->checksum_offset != -1)
	 && setsockopt (protofd, SOL_IPV6, IPV6_CHECKSUM, &type->checksum_offset,
	                sizeof (int)))
	{
		perror ("setsockopt(IPV6_CHECKSUM)");
		goto error;
	}

#ifdef IPV6_TCLASS
	/* Defines traffic class */
	setsockopt (protofd, SOL_IPV6, IPV6_TCLASS, &tclass, sizeof (tclass));
#endif

	/* Set ICMPv6 filter for echo replies */
	if (type->protocol == IPPROTO_ICMPV6)
	{
		// This is ok as long as only one “type” uses ICMPv6 as protocol
		struct icmp6_filter f;

		ICMP6_FILTER_SETBLOCKALL (&f);
		ICMP6_FILTER_SETPASS (ICMP6_ECHO_REPLY, &f);
		setsockopt (protofd, SOL_ICMPV6, ICMP6_FILTER, &f, sizeof (f));
	}

	/* Defines destination */
	memset (&dst, 0, sizeof (dst));
	if (connect_proto (protofd, &dst, dsthost, dstport, srchost, srcport))
		goto error;
	printf (_("%u hops max, "), max_ttl);
	printf (_("%lu byte packets\n"), (unsigned long)packet_len);

	/* Performs traceroute */
	for (ttl = min_ttl, val = 0; (ttl <= max_ttl) && !val; ttl++)
		val = probe_ttl (protofd, icmpfd, &dst, ttl,
		                 retries, timeout, delay, packet_len);

	/* Cleans up */
	close (protofd);
	close (icmpfd);
	return val > 0 ? 0 : -2;

error:
	close (protofd);
	close (icmpfd);
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

	printf (_(
"Usage: %s [options] <IPv6 hostname/address> [port number/packet length]\n"
"Print IPv6 network route to a host\n"), path);

	puts (_("\n"
"  -A  send TCP ACK probes\n"
"  -d  enable socket debugging\n"
"  -E  set TCP Explicit Congestion Notification bits in TCP packets\n"
"  -f  specify the initial hop limit (default: 1)\n"
/*"  -g  add a loose route\n"*/
"  -h  display this help and exit\n"
"  -I  use ICMPv6 Echo Request packets as probes\n"
"  -i  force outgoing network interface\n"
/*"  -l  display incoming packets hop limit (UDP)\n"*/
/*"  -l  set TCP probes byte size\n"*/
"  -m  set the maximum hop limit (default: 30)\n"
"  -N  perform reverse name lookups on the addresses of every hop\n"
"  -n  don't perform reverse name lookup on addresses\n"
"  -p  override source TCP port or base destination UDP port\n"
"  -q  override the number of probes per hop (default: 3)\n"
"  -r  do not route packets\n"
"  -S  send TCP SYN probes\n"
"  -s  specify the source IPv6 address of probe packets\n"
"  -t  set traffic class of probe packets\n"
"  -U  send UDP probes (default)\n"
"  -V, --version  display program version and exit\n"
/*"  -v, --verbose  display all kind of ICMPv6 errors\n"*/
"  -w  override the timeout for response in seconds (default: 5)\n"
"  -z  specify a time to wait (in ms) between each probes (default: 0)\n"
			/*  TCP: -t  UDP: -g? -t*/
	));

	return 0;
}


static int
version (void)
{
	drop_priv ();

	printf (_(
"traceroute6: TCP & UDP IPv6 traceroute tool %s ($Rev$)\n"
" built %s on %s\n"), VERSION, __DATE__, PACKAGE_BUILD_HOSTNAME);
	printf (_("Configured with: %s\n"), PACKAGE_CONFIGURE_INVOCATION);
	puts (_("Written by Remi Denis-Courmont\n"));

	printf (_("Copyright (C) %u-%u Remi Denis-Courmont\n"
"This is free software; see the source for copying conditions.\n"
"There is NO warranty; not even for MERCHANTABILITY or\n"
"FITNESS FOR A PARTICULAR PURPOSE.\n"), 2005, 2006);
	return 0;
}


static unsigned
parse_hlim (const char *str)
{
	char *end;
	unsigned long u = strtoul (str, &end, 0);
	if ((u > 255) || *end)
	{
		fprintf (stderr, _("%s: invalid hop limit\n"), str);
		return (unsigned)(-1);
	}
	return (unsigned)u;
}


static size_t
parse_plen (const char *str)
{
	char *end;
	unsigned long u = strtoul (str, &end, 0);
	if ((u > 65535) || *end)
	{
		fprintf (stderr, _("%s: invalid packet length\n"), str);
		return (size_t)(-1);
	}
	return (size_t)u;
}


static struct option opts[] = 
{
	{ "ack",      no_argument,       NULL, 'A' },
	{ "debug",    no_argument,       NULL, 'd' },
	{ "ecn",      no_argument,       NULL, 'E' },
	// -F is a stub
	{ "first",    required_argument, NULL, 'f' },
	{ "help",     no_argument,       NULL, 'h' },
	{ "icmp",     no_argument,       NULL, 'I' },
	{ "iface",    required_argument, NULL, 'i' },
	{ "max",      required_argument, NULL, 'm' },
	// -N is not really a stub, should have a long name
	{ "numeric",  no_argument,       NULL, 'n' },
	{ "port",     required_argument, NULL, 'p' },
	{ "retry",    required_argument, NULL, 'q' },
	{ "noroute",  no_argument,       NULL, 'r' },
	{ "syn",      no_argument,       NULL, 'S' },
	{ "source",   required_argument, NULL, 's' },
	{ "tclass",   required_argument, NULL, 't' },
	{ "udp",      no_argument,       NULL, 'U' },
	{ "version",  no_argument,       NULL, 'V' },
	/*{ "verbose",  no_argument,       NULL, 'v' },*/
	{ "wait",     required_argument, NULL, 'w' },
	// -x is a stub
	{ "delay",    required_argument, NULL, 'z' },
	{ NULL,       0,                 NULL, 0   }
};


static const char optstr[] = "AdEf:hIi:m:Nnp:q:rSs:t:UVw:xz:";

int
main (int argc, char *argv[])
{
	const char *dsthost, *srchost = NULL, *xxxport = NULL;
	size_t plen = 16;
	unsigned retries = 3, wait = 5, delay = 0, minhlim = 1, maxhlim = 30;
	int val;

	while ((val = getopt_long (argc, argv, optstr, opts, NULL)) != EOF)
	{
		switch (val)
		{
			case 'A':
				type = &ack_type;
				break;

			case 'd':
				debug = true;
				break;

			case 'E':
				ecn = true;
				break;

			case 'F': // stub (don't fragment)
				break;

			case 'f':
				if ((minhlim = parse_hlim (optarg)) == (unsigned)(-1))
					return 1;
				break;

			case 'h':
				return usage (argv[0]);

			case 'I':
				type = &echo_type;
				break;

			case 'i':
				strncpy (ifname, optarg, IFNAMSIZ - 1);
				ifname[IFNAMSIZ - 1] = '\0';
				break;

			case 'm':
				if ((maxhlim = parse_hlim (optarg)) == (unsigned)(-1))
					return 1;
				break;

			case 'N':
				/*
				 * FIXME: should we differenciate private addresses as
				 * tcptraceroute does?
				 */
				niflags &= ~NI_NUMERICHOST;
				break;

			case 'n':
				niflags |= NI_NUMERICHOST | NI_NUMERICSERV;
				break;

			case 'p':
				xxxport = optarg;
				break;

			case 'q':
			{
				char *end;
				unsigned long l = strtoul (optarg, &end, 0);
				if (*end || l > 255)
					return quick_usage (argv[0]);
				retries = l;
				break;
			}

			case 'r':
				sendflags |= MSG_DONTROUTE;
				break;

			case 'S':
				type = &syn_type;
				break;

			case 's':
				srchost = optarg;
				break;

			case 't':
			{
				char *end;
				unsigned long l = strtoul (optarg, &end, 0);
				if (*end || l > 255)
					return quick_usage (argv[0]);
				tclass = l;
				break;
			}

			case 'U':
				type = &udp_type;
				break;

			case 'V':
				return version ();

			case 'w':
			{
				char *end;
				unsigned long l = strtoul (optarg, &end, 0);
				if (*end || l > UINT_MAX)
					return quick_usage (argv[0]);
				wait = (unsigned)l;
				break;
			}

			case 'x': // stub: no IPv6 checksums
				break;

			case 'z':
			{
				char *end;
				unsigned long l = strtoul (optarg, &end, 0);
				if (*end || l > UINT_MAX)
					return quick_usage (argv[0]);
				delay = (unsigned)l;
				break;
			}

			case '?':
			default:
				return quick_usage (argv[0]);
		}
	}

	if (type == NULL)
		type = &udp_type;

	const char *srcport = NULL, *dstport = NULL;

	if (type->protocol == IPPROTO_TCP)
		srcport = xxxport;
	else
		dstport = xxxport;

	if (optind < argc)
	{
		dsthost = argv[optind++];

		if (optind < argc)
		{
			if (type->protocol == IPPROTO_TCP)
				dstport = argv[optind++];
			else
			if ((plen = parse_plen (argv[optind++])) == (size_t)(-1))
				return 1;
		}
	}
	else
		return quick_usage (argv[0]);

	if (dstport == NULL)
		dstport = (type->protocol == IPPROTO_TCP) ? "80" : "33434";

	setvbuf (stdout, NULL, _IONBF, 0);
	return -traceroute (dsthost, dstport, srchost, srcport, wait, delay,
	                    retries, plen, minhlim, maxhlim);
}
