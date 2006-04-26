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

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h> /* div() */
#include <limits.h>
#include <stdbool.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h> // IFNAMSIZ
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/icmp6.h>
#include <netdb.h>
#include <arpa/inet.h> /* inet_ntop() */
#include <fcntl.h>
#include <errno.h>
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif
#ifndef SOL_IPV6
# define SOL_IPV6 IPPROTO_IPV6
#endif
#ifndef SOL_ICMPV6
# define SOL_ICMPV6 IPPROTO_ICMPV6
#endif


typedef struct tracetype
{
	int gai_socktype;
	int protocol;
	int checksum_offset;
	int (*send_probe) (int fd, unsigned ttl, unsigned n, uint16_t port);
	int (*parse_resp) (const void *data, size_t len, unsigned *ttl,
	                   unsigned *n, uint16_t port);
	int (*parse_err) (const void *data, size_t len, unsigned *ttl,
	                  unsigned *n, uint16_t port);
} tracetype;


static int niflags = 0;
static int sendflags = 0;
static int tcpflags = 0;
static const tracetype *type = NULL;
bool debug = false;
static char ifname[IFNAMSIZ] = "";

#define TCP_WINDOW 4096
#ifndef TH_ECE
# define TH_ECE 0x40
# define TH_CWR 0x80
#endif


/****************************************************************************/

static void
drop_priv (void)
{
	setuid (getuid ());
}


static uint16_t getsourceport (void)
{
	static uint16_t p = 0;

	if (p == 0)
	{
		uint16_t v = ~getpid ();
		if (v < 1025)
			v += 1025;
		p = htons (v);
	}
	return p;
}


static int send_payload (int fd, const void *payload, size_t length)
{
	return send (fd, payload, length, sendflags) == (int)length ? 0 : -1;
}


/* UDP probes (traditional traceroute) */
static int
send_udp_probe (int fd, unsigned ttl, unsigned n, uint16_t port)
{
	struct udphdr uh;
	memset (&uh, 0, sizeof (uh));

	(void)n;
	uh.uh_sport = getsourceport ();
	uh.uh_dport = htons (ntohs (port) + ttl);
	uh.uh_ulen = htons (sizeof (uh));

	return send_payload (fd, &uh, sizeof (uh));
}


static int
parse_udp_error (const void *data, size_t len, unsigned *ttl, unsigned *n,
                 uint16_t port)
{
	const struct udphdr *puh = (const struct udphdr *)data;
	uint16_t rport;

	if ((len < 6)
	 || (puh->uh_sport != getsourceport ())
	 || (puh->uh_ulen != htons (sizeof (*puh))))
		return -1;

	rport = ntohs (puh->uh_dport);
	port = ntohs (port);
	if ((rport < port) || (rport > port + 255))
		return -1;

	*ttl = rport - port;
	*n = (unsigned)(-1);
	return 0;
}


static const tracetype udp_type =
	{ SOCK_DGRAM, IPPROTO_UDP, 6,
	  send_udp_probe, NULL, parse_udp_error };


/* ICMPv6 Echo probes */
static int
send_echo_probe (int fd, unsigned ttl, unsigned n, uint16_t port)
{
	struct icmp6_hdr ih;
	memset (&ih, 0, sizeof (ih));

	ih.icmp6_type = ICMP6_ECHO_REQUEST;
	ih.icmp6_id = htons (getpid ());
	ih.icmp6_seq = htons ((ttl << 8) | (n & 0xff));
	(void)port;

	return send_payload (fd, &ih, sizeof (ih));
}


static int
parse_echo_reply (const void *data, size_t len, unsigned *ttl, unsigned *n,
                  uint16_t port)
{
	const struct icmp6_hdr *pih = (const struct icmp6_hdr *)data;

	if ((len < sizeof (*pih))
	 || (pih->icmp6_type != ICMP6_ECHO_REPLY)
	 || (pih->icmp6_id != htons (getpid ())))
		return -1;

	(void)port;

	*ttl = ntohs (pih->icmp6_seq) >> 8;
	*n = ntohs (pih->icmp6_seq) & 0xff;
	return 0;
}


static int
parse_echo_error (const void *data, size_t len, unsigned *ttl, unsigned *n,
                  uint16_t port)
{
	const struct icmp6_hdr *pih = (const struct icmp6_hdr *)data;

	if ((len < sizeof (*pih))
	 || (pih->icmp6_type != ICMP6_ECHO_REQUEST) || (pih->icmp6_code)
	 || (pih->icmp6_id != htons (getpid ())))
		return -1;

	(void)port;

	*ttl = ntohs (pih->icmp6_seq) >> 8;
	*n = ntohs (pih->icmp6_seq) & 0xff;
	return 0;
}


static const tracetype echo_type =
	{ SOCK_DGRAM, IPPROTO_ICMPV6, 2,
	  send_echo_probe, parse_echo_reply, parse_echo_error };


/* TCP/SYN probes */
static int
send_syn_probe (int fd, unsigned ttl, unsigned n, uint16_t port)
{
	struct tcphdr th;

	memset (&th, 0, sizeof (th));
	th.th_sport = getsourceport ();
	th.th_dport = port;
	th.th_seq = htonl ((ttl << 24) | (n << 16) | getpid ());
	th.th_off = sizeof (th) / 4;
	th.th_flags = TH_SYN | tcpflags;
	th.th_win = htons (TCP_WINDOW);

	return send_payload (fd, &th, sizeof (th));
}


static int
parse_syn_resp (const void *data, size_t len, unsigned *ttl, unsigned *n,
                uint16_t port)
{
	const struct tcphdr *pth = (const struct tcphdr *)data;
	uint32_t seq;

	if ((len < sizeof (*pth))
	 || (pth->th_dport != getsourceport ())
	 || (pth->th_sport != port)
	 || ((pth->th_flags & TH_ACK) == 0)
	 || (((pth->th_flags & TH_SYN) != 0) == ((pth->th_flags & TH_RST) != 0))
	 || (pth->th_off < (sizeof (*pth) / 4)))
		return -1;

	seq = ntohl (pth->th_ack) - 1;
	if ((seq & 0xffff) != (unsigned)getpid ())
		return -1;

	*ttl = seq >> 24;
	*n = (seq >> 16) & 0xff;
	return 1 + ((pth->th_flags & TH_SYN) == TH_SYN);
}


static int
parse_syn_error (const void *data, size_t len, unsigned *ttl, unsigned *n,
                 uint16_t port)
{
	const struct tcphdr *pth = (const struct tcphdr *)data;
	uint32_t seq;

	if ((len < 8)
	 || (pth->th_sport != getsourceport ())
	 || (pth->th_dport != port))
		return -1;

	seq = ntohl (pth->th_seq);
	if ((seq & 0xffff) != (unsigned)getpid ())
		return -1;

	*ttl = seq >> 24;
	*n = (seq >> 16) & 0xff;
	return 0;
}


static const tracetype syn_type =
	{ SOCK_STREAM, IPPROTO_TCP, 16,
	  send_syn_probe, parse_syn_resp, parse_syn_error };


/* TCP/ACK probes */
static int
send_ack_probe (int fd, unsigned ttl, unsigned n, uint16_t port)
{
	struct tcphdr th;

	memset (&th, 0, sizeof (th));
	th.th_sport = getsourceport ();
	th.th_dport = port;
	th.th_ack = htonl ((ttl << 24) | (n << 16) | getpid ());
	th.th_off = sizeof (th) / 4;
	th.th_flags = TH_ACK;
	th.th_win = htons (TCP_WINDOW);

	return send_payload (fd, &th, sizeof (th));
}


static int
parse_ack_resp (const void *data, size_t len, unsigned *ttl, unsigned *n,
                uint16_t port)
{
	const struct tcphdr *pth = (const struct tcphdr *)data;
	uint32_t seq;

	if ((len < sizeof (*pth))
	 || (pth->th_dport != getsourceport ())
	 || (pth->th_sport != port)
	 || (pth->th_flags & TH_SYN)
	 || (pth->th_flags & TH_ACK)
	 || ((pth->th_flags & TH_RST) == 0)
	 || (pth->th_off < (sizeof (*pth) / 4)))
		return -1;

	seq = ntohl (pth->th_seq);
	if ((seq & 0xffff) != (unsigned)getpid ())
		return -1;

	*ttl = seq >> 24;
	*n = (seq >> 16) & 0xff;
	return 0;
}


static int
parse_ack_error (const void *data, size_t len, unsigned *ttl, unsigned *n,
                 uint16_t port)
{
	const struct tcphdr *pth = (const struct tcphdr *)data;
	uint32_t seq;

	if ((len < 8)
	 || (pth->th_sport != getsourceport ())
	 || (pth->th_dport != port))
		return -1;

	seq = ntohl (pth->th_ack);
	if ((seq & 0xffff) != (unsigned)getpid ())
		return -1;

	*ttl = seq >> 24;
	*n = (seq >> 16) & 0xff;
	return 0;
}


static const tracetype ack_type =
	{ SOCK_STREAM, IPPROTO_TCP, 16,
	  send_ack_probe, parse_ack_resp, parse_ack_error };


/* Performs reverse lookup; print hostname and address */
static void
printname (const struct sockaddr *addr, size_t addrlen)
{
	char name[NI_MAXHOST];
	int val;

	val = getnameinfo (addr, addrlen, name, sizeof (name), NULL, 0, niflags);
	if (!val)
		printf (" %s", name);

	val = getnameinfo (addr, addrlen, name, sizeof (name), NULL, 0,
	                   NI_NUMERICHOST | niflags);
	if (!val)
		printf (" (%s) ", name);
}


/* Prints delay between two dates */
static void
printdelay (const struct timeval *from, const struct timeval *to)
{
	div_t d;
	if (to->tv_usec < from->tv_usec)
	{
		d = div (1000000 + to->tv_usec - from->tv_usec, 1000);
		d.quot -= 1000;
	}
	else
		d = div (to->tv_usec - from->tv_usec, 1000);

	printf (_(" %u.%03u ms "),
	        (unsigned)(d.quot + 1000 * (to->tv_sec - from->tv_sec)),
	        (unsigned)d.rem);
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
           unsigned ttl, unsigned retries, unsigned timeout)
{
	struct in6_addr hop; /* hop if known from previous probes */
	unsigned n;
	int found = 0;
	int state = -1; /* type of response received so far (-1: none,
		0: normal, 1: closed, 2: open) */
	/* see also: found (0: not found, <0: unreachable, >0: reached) */

	memset (&hop, 0, sizeof (hop));
	printf ("%2d ", ttl);
	setsockopt (protofd, SOL_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof (ttl));

	for (n = 0; n < retries; n++)
	{
		struct timeval tv = { timeout, 0 }, sent, recvd;
		unsigned pttl, pn;
		int maxfd;

		maxfd = 1 + (icmpfd > protofd ? icmpfd : protofd);

		gettimeofday (&sent, NULL);
		if (type->send_probe (protofd, ttl, n, dst->sin6_port))
		{
			perror (_("Cannot send packet"));
			return -1;
		}

		for (;;)
		{
			fd_set rdset;
			int val;

			FD_ZERO (&rdset);
			FD_SET (icmpfd, &rdset);
			FD_SET (protofd, &rdset);

			val = select (maxfd, &rdset, NULL, NULL, &tv);
			if (val < 0) /* interrupted by signal - well, not really */
				return -1;

			if (val == 0)
			{
				fputs (" *", stdout);
				break;
			}

			gettimeofday (&recvd, NULL);

			/* Receive final packet when host reached */
			if (FD_ISSET (protofd, &rdset))
			{
				uint8_t buf[1240];
				int len;

				len = recv (protofd, buf, sizeof (buf), 0);
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
						printname ((struct sockaddr *)dst, sizeof (*dst));
						state = 1;
						found = ttl;
					}
					printdelay (&sent, &recvd);
					break;
				}

				if (type->parse_resp == NULL)
					continue;

				len = type->parse_resp (buf, len, &pttl, &pn, dst->sin6_port);
				if ((len >= 0) && (n == pn) && (pttl = ttl))
				{
					/* Route determination complete! */
					if (state == -1)
						printname ((struct sockaddr *)dst, sizeof (*dst));

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
			if (val && FD_ISSET (icmpfd, &rdset))
			{
				struct
				{
					struct icmp6_hdr hdr;
					struct ip6_hdr inhdr;
					uint8_t buf[1192];
				} pkt;
				struct sockaddr_in6 peer;
				socklen_t peerlen = sizeof (peer);
				int len;

				len = recvfrom (icmpfd, &pkt, sizeof (pkt), 0,
				                (struct sockaddr *)&peer, &peerlen);

				if ((len < (int)(sizeof (pkt.hdr) + sizeof (pkt.inhdr)))
				 || ((pkt.hdr.icmp6_type != ICMP6_DST_UNREACH)
				  && ((pkt.hdr.icmp6_type != ICMP6_TIME_EXCEEDED)
				   || (pkt.hdr.icmp6_code != ICMP6_TIME_EXCEED_TRANSIT)))
				 || memcmp (&pkt.inhdr.ip6_dst, &dst->sin6_addr, 16)
				 || (pkt.inhdr.ip6_nxt != type->protocol))
					continue;
				len -= sizeof (pkt.hdr) + sizeof (pkt.inhdr);

				len = type->parse_err (pkt.buf, len, &pttl, &pn,
				                       dst->sin6_port);
				if ((len < 0) || (pttl != ttl)
				 || ((pn != n) && (pn != (unsigned)(-1))))
					continue;

				/* genuine ICMPv6 error that concerns us */
				if ((state == -1) || memcmp (&hop, &peer.sin6_addr, 16))
				{
					memcpy (&hop, &peer.sin6_addr, 16);
					printname ((struct sockaddr *)&peer, peerlen);
					state = 0;
				}

				if ((found == 0) && (pkt.hdr.icmp6_type == ICMP6_DST_UNREACH))
				{
					if (pkt.hdr.icmp6_code == ICMP6_DST_UNREACH_NOPORT)
						found = ttl;
					else
						found = -ttl;
				}

				printdelay (&sent, &recvd);
				print_icmp_code (&pkt.hdr);
				break;
			}
		}
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
	int val;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = type->gai_socktype;

	if ((srchost != NULL) || (srcport != NULL))
	{
		hints.ai_flags |= AI_PASSIVE;

		if (getaddrinfo_err (srchost, srcport, &hints, &res))
			return -1;

		val = bind (fd, res->ai_addr, res->ai_addrlen);
		freeaddrinfo (res);

		if (val)
		{
			perror (srchost);
			return -1;
		}
		hints.ai_flags &= ~AI_PASSIVE;
	}

	if (getaddrinfo_err (dsthost, dstport, &hints, &res))
		return -1;

	if (res->ai_addrlen > sizeof (*dst))
	{
		freeaddrinfo (res);
		return -1;
	}

	val = connect (fd, res->ai_addr, res->ai_addrlen);
	if (val == 0)
	{
		char buf[INET6_ADDRSTRLEN];
		socklen_t len = sizeof (*dst);

		fputs (_("traceroute to"), stdout);
		printname (res->ai_addr, res->ai_addrlen);
		if ((getsockname (fd, (struct sockaddr *)dst, &len) == 0)
		 && inet_ntop (AF_INET6, &dst->sin6_addr, buf, sizeof (buf)))
			printf (_("from %s, "), buf);

		memcpy (dst, res->ai_addr, res->ai_addrlen);
	}
	freeaddrinfo (res);
	
	if (val)
	{
		perror (dsthost);
		return -1;
	}

	return 0;
}


static void setup_socket (int fd)
{
	int val = 1;

	if (debug)
		setsockopt (fd, SOL_SOCKET, SO_DEBUG, &val, sizeof (val));
	setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof (val));

	val = fcntl (fd, F_GETFL);
	if (val == -1)
		val = 0;
	fcntl (fd, F_SETFL, O_NONBLOCK | val);
	fcntl (fd, F_GETFD, FD_CLOEXEC);
}


static int
traceroute (const char *dsthost, const char *dstport,
            const char *srchost, const char *srcport,
            unsigned timeout, unsigned retries,
            unsigned min_ttl, unsigned max_ttl)
{
	struct sockaddr_in6 dst;
	int protofd, icmpfd, val;
	unsigned ttl;

	/* Creates ICMPv6 socket to collect error packets */
	icmpfd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (icmpfd == -1)
	{
		perror (_("Raw socket"));
		return -1;
	}

	/* Creates protocol-specific socket */
	protofd = socket (AF_INET6, SOCK_RAW, type->protocol);
	if (protofd == -1)
	{
		perror (_("Raw socket"));
		close (icmpfd);
		return -1;
	}

	if (*ifname
	 && setsockopt (protofd, SOL_SOCKET, SO_BINDTODEVICE, ifname,
	                strlen (ifname) + 1))
	{
		perror (ifname);
		close (protofd);
		close (icmpfd);
		return -1;
	}

	/* Drops privileges permanently */
	drop_priv ();

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
	printf (_("port %u, "), ntohs (dst.sin6_port));
	printf (_("%u hops max\n"), max_ttl);

	setsockopt (protofd, SOL_SOCKET, SO_BINDTODEVICE, ifname,
				strlen (ifname) + 1);

	/* Performs traceroute */
	for (ttl = min_ttl, val = 0; (ttl <= max_ttl) && !val; ttl++)
		val = probe_ttl (protofd, icmpfd, &dst, ttl, retries, timeout);

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
"  -h  display this help and exit\n"
"  -I  use ICMPv6 Echo Request packets as probes\n"
"  -i  force outgoing network interface\n"
/*"  -l  display incoming packets hop limit (UDP)\n"*/
/*"  -l  set TCP probes byte size\n"*/
"  -m  set the maximum hop limit (default: 30)\n"
"  -N  perform reverse name lookups on the addresses of every hop\n"
"  -n  don't perform reverse name lookup on addresses\n"
/*"  -p  override base destination UDP port\n"*/
/*"  -p  override source TCP port\n"*/
"  -q  override the number of probes per hop (default: 3)\n"
"  -r  do not route packets\n"
"  -S  send TCP SYN probes\n"
"  -s  specify the source IPv6 address of probe packets\n"
"  -U  send UDP probes (default)\n"
"  -V, --version  display program version and exit\n"
/*"  -v, --verbose  display all kind of ICMPv6 errors\n"*/
"  -w  override the timeout for response in seconds (default: 5)\n"
/*"  -z  specify a time to wait (in ms) between each probes (default: 0)\n"*/
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


static int
parse_hlim (const char *str)
{
	char *end;
	unsigned long u;

	u = strtoul (str, &end, 0);
	if ((u > 255) || *end)
	{
		fprintf (stderr, _("%s: invalid hop limit\n"), str);
		return -1;
	}
	return u;
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
	{ "retry",    required_argument, NULL, 'q' },
	{ "noroute",  no_argument,       NULL, 'r' },
	{ "syn",      no_argument,       NULL, 'S' },
	{ "source",   required_argument, NULL, 's' },
	{ "udp",      no_argument,       NULL, 'U' },
	{ "version",  no_argument,       NULL, 'V' },
	/*{ "verbose",  no_argument,       NULL, 'v' },*/
	{ "wait",     required_argument, NULL, 'w' },
	// -x is a stub
	{ NULL,       0,                 NULL, 0   }
};


static const char optstr[] = "AdEf:hIi:m:Nnq:rSs:UVw:x";

int
main (int argc, char *argv[])
{
	int val;
	unsigned retries = 3, wait = 5, minhlim = 1, maxhlim = 30;
	const char *dsthost, *dstport, *srchost = NULL, *srcport = NULL;

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
				tcpflags |= TH_ECE | TH_CWR;
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

			case 'q':
			{
				unsigned long l;
				char *end;

				l = strtoul (optarg, &end, 0);
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

			case 'U':
				type = &udp_type;
				break;

			case 'V':
				return version ();

			case 'w':
			{
				unsigned long l;
				char *end;

				l = strtoul (optarg, &end, 0);
				if (*end || l > UINT_MAX)
					return quick_usage (argv[0]);
				wait = l;
				break;
			}

			// stubs:
			case 'F':
			case 'x':
				break;

			case '?':
			default:
				return quick_usage (argv[0]);
		}
	}

	if (type == NULL)
		type = &udp_type;

	/* FIXME: use dstport as packet size for UDP and ICMP */
	if (optind < argc)
	{
		dsthost = argv[optind++];

		if (optind < argc)
			dstport = argv[optind++];
		else
			dstport = (type->protocol == IPPROTO_TCP) ? "80" : "33434";
	}
	else
		return quick_usage (argv[0]);

	setvbuf (stdout, NULL, _IONBF, 0);
	return -traceroute (dsthost, dstport, srchost, srcport, wait, retries,
	                    minhlim, maxhlim);
}
