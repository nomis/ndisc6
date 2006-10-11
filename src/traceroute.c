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
#include <net/if.h> // IFNAMSIZ, if_nametoindex
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netdb.h>
#include <arpa/inet.h> /* inet_ntop() */
#include <fcntl.h>
#include <errno.h>
#include <locale.h> /* setlocale() */
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

#include "gettime.h"
#include "inet6rth.h"
#include "traceroute.h"

#ifndef AI_IDN
# define AI_IDN 0
#endif

#ifndef IPV6_TCLASS
# if defined (__linux__)
#  define IPV6_TCLASS 67
# elif defined (__FreeBSD__) || defined (__FreeBSD_kernel__) \
    || defined (__NetBSD__)  || defined (__NetBSD_kernel__)
#  define IPV6_TCLASS 61
# else
#  warning Traffic class support missing! Define IPV6_TCLASS!
# endif
#endif

#ifndef IPV6_RECVHOPLIMIT
/* Using obsolete RFC 2292 instead of RFC 3542 */
# define IPV6_RECVHOPLIMIT IPV6_HOPLIMIT
#endif

#ifndef SOL_IPV6
# define SOL_IPV6 IPPROTO_IPV6
#endif
#ifndef SOL_ICMPV6
# define SOL_ICMPV6 IPPROTO_ICMPV6
#endif


/* All our evil global variables */
static const tracetype *type = NULL;
static int niflags = 0;
static int tclass = -1;
uint16_t sport;
static bool debug = false, dontroute = false, show_hlim = false;
bool ecn = false;
static char ifname[IFNAMSIZ] = "";

static const char *rt_segv[127];
static int rt_segc = 0;

/****************************************************************************/

static uint16_t getsourceport (void)
{
	uint16_t v = ~getpid ();
	if (v < 1025)
		v += 1025;
	return htons (v);
}


ssize_t send_payload (int fd, const void *payload, size_t length)
{
	ssize_t rc = send (fd, payload, length, 0);

	if (rc == (ssize_t)length)
		return 0;

	if (rc != -1)
		errno = EMSGSIZE;
	return -1;
}


static ssize_t
recv_payload (int fd, void *buf, size_t len,
              struct sockaddr_in6 *addr, int *hlim)
{
	char cbuf[CMSG_SPACE (sizeof (int))];
	struct iovec iov =
	{
		.iov_base = buf,
		.iov_len = len
	};
	struct msghdr hdr =
	{
		.msg_name = addr,
		.msg_namelen = (addr != NULL) ? sizeof (*addr) : 0,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof (cbuf)
	};

	ssize_t val = recvmsg (fd, &hdr, 0);
	if (val == -1)
		return val;

	/* ensures the hop limit is 255 */
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR (&hdr);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR (&hdr, cmsg))
		if ((cmsg->cmsg_level == IPPROTO_IPV6)
		 && (cmsg->cmsg_type == IPV6_HOPLIMIT))
			memcpy (hlim, CMSG_DATA (cmsg), sizeof (hlim));

	return val;
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


static inline void print_hlim (int hlim)
{
	if (hlim != -1)
		printf (_("(%d) "), hlim);
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


static ssize_t
parse (trace_parser_t func, const void *data, size_t len,
       unsigned hlim, unsigned retry, uint16_t port)
{
	unsigned rhlim, rretry;

	ssize_t rc = func (data, len, &rhlim, &rretry, port);
	if (rc < 0)
		return rc;

	if (rhlim != hlim)
		return -1;

	if ((rretry != (unsigned)(-1)) && (rretry != retry))
		return -1;

	return rc;
}


static const void *
skip_exthdrs (struct ip6_hdr *ip6, size_t *plen)
{
	const uint8_t *payload = (const uint8_t *)(ip6 + 1);
	size_t len = *plen;
	uint8_t nxt = ip6->ip6_nxt;

	for (;;)
	{
		uint16_t hlen;

		switch (nxt)
		{
			case IPPROTO_HOPOPTS:
			case IPPROTO_DSTOPTS:
			case IPPROTO_ROUTING:
				if (len < 2)
					return NULL;

				hlen = (1 + (uint16_t)payload[1]) << 3;
				break;

			case IPPROTO_FRAGMENT:
				hlen = 8;
				break;

			case IPPROTO_AH:
				if (len < 2)
					return NULL;

				hlen = (2 + (uint16_t)payload[1]) << 2;
				break;

			default: // THE END
				goto out;
		}

		if (len < hlen)
			return NULL; // too short;

		switch (nxt)
		{
			case IPPROTO_ROUTING:
			{
				/* Extract real destination */
				if (payload[3] > 0) // segments left
				{
					if (payload[2] != 0)
						return NULL; // unknown type
	
					/* Handle Routing Type 0 */
					if ((hlen & 8) != 8)
						return NULL; // != 8[16] -> invalid length

					memcpy (&ip6->ip6_dst,
					        payload + (16 * payload[3]) - 8, 16);
				}
				break;
			}

			case IPPROTO_FRAGMENT:
			{
				uint16_t offset;
				memcpy (&offset, payload + 2, 2);
				if (ntohs (offset) >> 3)
					return NULL; // non-first fragment
				break;
			}
		}

		nxt = payload[0];
		len -= hlen;
		payload += hlen;
	}

out:
	ip6->ip6_nxt = nxt;
	*plen = len;
	return payload;
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

		mono_gettime (&sent);
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

			mono_gettime (&recvd);
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

			mono_gettime (&recvd);

			/* Receive final packet when host reached */
			if (ufds[0].revents)
			{
				uint8_t buf[1240];
				int hlim = -1;
				ssize_t len;

				len = recv_payload (protofd, buf, sizeof (buf), NULL, &hlim);
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
					}
					printdelay (&sent, &recvd);
					found = ttl;
					break; // response received, stop poll()ing
				}

				if (type->parse_resp == NULL)
					continue;

				len = parse (type->parse_resp, buf, len, ttl, n,
				             dst->sin6_port);
				if (len >= 0)
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
					print_hlim (hlim);
					found = ttl;
					break; // response received, stop poll()ing
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
				int hlim = -1;

				ssize_t len = recv_payload (icmpfd, &pkt, sizeof (pkt),
				                            &peer, &hlim);

				if (len < (ssize_t)(sizeof (pkt.hdr) + sizeof (pkt.inhdr)))
					continue; // too small

				len -= sizeof (pkt.hdr) + sizeof (pkt.inhdr);

				const void *buf = skip_exthdrs (&pkt.inhdr, (size_t *)&len);

				if (memcmp (&pkt.inhdr.ip6_dst, &dst->sin6_addr, 16))
					continue; // wrong destination

				if (pkt.inhdr.ip6_nxt != type->protocol)
					continue; // wrong protocol

				len = parse (type->parse_err, buf, len, ttl, n,
				             dst->sin6_port);
				if (len < 0)
					continue;

				/* genuine ICMPv6 error that concerns us */
				switch (pkt.hdr.icmp6_type)
				{
					case ICMP6_DST_UNREACH:
						switch (pkt.hdr.icmp6_code)
						{
							case ICMP6_DST_UNREACH_NOPORT:
								found = ttl;
								break;

							default:
								if (found == 0)
									found = -ttl;
						}
						break;

					case ICMP6_TIME_EXCEEDED:
						if (pkt.hdr.icmp6_code == ICMP6_TIME_EXCEED_TRANSIT)
							break;

					default: // should not happen (ICMPv6 filter)
						continue;
				}

				if ((state == -1) || memcmp (&hop, &peer.sin6_addr, 16))
				{
					memcpy (&hop, &peer.sin6_addr, 16);
					printipv6 (&peer);
					state = 0;
				}

				printdelay (&sent, &recvd);
				print_hlim (hlim);
				print_icmp_code (&pkt.hdr);
				break; // response received, stop poll()ing
			}
		}

		if (delay)
			mono_nanosleep (&delay_ts);
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
	hints.ai_flags = AI_IDN;

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
		setsockopt (fd, SOL_SOCKET, SO_DEBUG, &(int){ 1 }, sizeof (int));
	setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof (int));

	if (show_hlim)
		setsockopt (fd, SOL_IPV6, IPV6_RECVHOPLIMIT, &(int){1}, sizeof (int));

	int val = fcntl (fd, F_GETFL);
	if (val == -1)
		val = 0;
	fcntl (fd, F_SETFL, O_NONBLOCK | val);
	fcntl (fd, F_GETFD, FD_CLOEXEC);
}


static int setsock_rth (int fd, int type, const char **segv, int segc)
{
	uint8_t hdr[inet6_rth_space (type, segc)];
	inet6_rth_init (hdr, sizeof (hdr), type, segc);

	struct addrinfo hints;
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_INET6;
	hints.ai_flags = AI_IDN;

	for (int i = 0; i < segc; i++)
	{
		struct addrinfo *res;

		if (getaddrinfo_err (segv[i], NULL, &hints, &res))
			return -1;

		const struct sockaddr_in6 *a = (const void *)res->ai_addr;
		if (inet6_rth_add (hdr, &a->sin6_addr))
			return -1;
	}

#ifdef IPV6_RTHDR
	return setsockopt (fd, SOL_IPV6, IPV6_RTHDR, hdr, sizeof (hdr));
#else
	errno = ENOSYS;
	return -1;
#endif
}


/* Requests raw sockets ahead of use so we can drop root quicker */
static struct
{
	int protocol;
	int fd;
	int errnum;
} protofd[] =
{
	{ IPPROTO_ICMPV6, -1, EPERM },
	{ IPPROTO_ICMPV6, -1, EPERM },
	{ IPPROTO_UDP,    -1, EPERM },
	{ IPPROTO_TCP,    -1, EPERM }
};


static int prepare_sockets (void)
{
	for (unsigned i = 0; i < sizeof (protofd) / sizeof (protofd[0]); i++)
	{
		protofd[i].fd = socket (AF_INET6, SOCK_RAW, protofd[i].protocol);
		if (protofd[i].fd == -1)
			protofd[i].errnum = errno;
		else
		if (protofd[i].fd <= 2)
			return -1;
	}
	return 0;
}


static int get_socket (int protocol)
{
	for (unsigned i = 0; i < sizeof (protofd) / sizeof (protofd[0]); i++)
		if (protofd[i].protocol == protocol)
		{
			int fd = protofd[i].fd;
			if (fd != -1)
			{
				protofd[i].fd = -1;
				return fd;
			}
			errno = protofd[i].errnum;
		}

	return -1;
}


static void drop_sockets (void)
{
	for (unsigned i = 0; i < sizeof (protofd) / sizeof (protofd[0]); i++)
		if (protofd[i].fd != -1)
			close (protofd[i].fd);
}


static int
traceroute (const char *dsthost, const char *dstport,
            const char *srchost, const char *srcport,
            unsigned timeout, unsigned delay, unsigned retries,
            size_t packet_len, unsigned min_ttl, unsigned max_ttl)
{
	/* Creates ICMPv6 socket to collect error packets */
	int icmpfd = get_socket (IPPROTO_ICMPV6);
	if (icmpfd == -1)
	{
		perror (_("Raw IPv6 socket"));
		return -1;
	}

	/* Creates protocol-specific socket */
	int protofd = get_socket (type->protocol);
	if (protofd == -1)
	{
		perror (_("Raw IPv6 socket"));
		close (icmpfd);
		return -1;
	}

	drop_sockets ();

#ifdef IPV6_PKTINFO
	/* Set outgoing interface */
	if (*ifname)
	{
		struct in6_pktinfo nfo;

		memset (&nfo, 0, sizeof (nfo));
		nfo.ipi6_ifindex = if_nametoindex (ifname);
		if (nfo.ipi6_ifindex == 0)
		{
			fprintf (stderr, _("%s: %s\n"), ifname, strerror (ENXIO));
			goto error;
		}

		if (setsockopt (protofd, SOL_IPV6, IPV6_PKTINFO, &nfo, sizeof (nfo)))
		{
			perror (ifname);
			goto error;
		}
	}
#endif

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

	if (dontroute)
		setsockopt (protofd, SOL_SOCKET, SO_DONTROUTE, &(int){ 1 },
		            sizeof (int));

	/* Defines Type 0 Routing Header */
	if (rt_segc > 0)
		setsock_rth (protofd, IPV6_RTHDR_TYPE_0, rt_segv, rt_segc);

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
	struct sockaddr_in6 dst;
	memset (&dst, 0, sizeof (dst));
	if (connect_proto (protofd, &dst, dsthost, dstport, srchost, srcport))
		goto error;
	printf (_("%u hops max, "), max_ttl);
	printf (_("%lu byte packets\n"), (unsigned long)packet_len);

	/* Performs traceroute */
	int val = 0;
	for (unsigned ttl = min_ttl; ttl <= max_ttl; ttl++)
	{
		val = probe_ttl (protofd, icmpfd, &dst, ttl,
		                 retries, timeout, delay, packet_len);
		if (val)
			break;
	}

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
	fprintf (stderr, _("Try \"%s -h\" for more information.\n"), path);
	return 2;
}


static int
usage (const char *path)
{
	printf (_(
"Usage: %s [options] <IPv6 hostname/address> [packet length]\n"
"Print IPv6 network route to a host\n"), path);

	puts (_("\n"
"  -A  send TCP ACK probes\n"
"  -d  enable socket debugging\n"
"  -E  set TCP Explicit Congestion Notification bits in TCP packets\n"
"  -f  specify the initial hop limit (default: 1)\n"
"  -g  insert a route segment within a \"Type 0\" routing header\n"
"  -h  display this help and exit\n"
"  -I  use ICMPv6 Echo Request packets as probes\n"
"  -i  force outgoing network interface\n"
"  -l  display incoming packets hop limit\n"
"  -m  set the maximum hop limit (default: 30)\n"
"  -N  perform reverse name lookups on the addresses of every hop\n"
"  -n  don't perform reverse name lookup on addresses\n"
"  -p  override destination port\n"
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
	));

	return 0;
}


static int
version (void)
{
	printf (_(
"traceroute6: TCP & UDP IPv6 traceroute tool %s (%s)\n"
" built %s on %s\n"), VERSION, "$Rev$",
	        __DATE__, PACKAGE_BUILD_HOSTNAME);
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


static const struct option opts[] = 
{
	{ "ack",      no_argument,       NULL, 'A' },
	{ "debug",    no_argument,       NULL, 'd' },
	{ "ecn",      no_argument,       NULL, 'E' },
	// -F is a stub
	{ "first",    required_argument, NULL, 'f' },
	{ "segment",  required_argument, NULL, 'g' },
	{ "help",     no_argument,       NULL, 'h' },
	{ "icmp",     no_argument,       NULL, 'I' },
	{ "iface",    required_argument, NULL, 'i' },
	{ "hlim",     no_argument,       NULL, 'l' },
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


static const char optstr[] = "AdEFf:g:hIi:lm:Nnp:q:rSs:t:UVw:xz:";

int
main (int argc, char *argv[])
{
	if (prepare_sockets () || setuid (getuid ()))
		return 1;

	setlocale (LC_CTYPE, "");

	const char *dsthost, *srchost = NULL, *dstport = "33434", *srcport = NULL;
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

			case 'g':
				if (rt_segc >= 127)
				{
					fprintf (stderr,
					         "%s: Too many route segments specified.\n",
					         optarg);
					return 1;
				}
				rt_segv[rt_segc++] = optarg;
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

			case 'l':
				show_hlim = true;
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
				dstport = optarg;
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
				dontroute = true;
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

	if (optind >= argc)
		return quick_usage (argv[0]);

	dsthost = argv[optind++];

	if (optind < argc)
	{
		plen = parse_plen (argv[optind++]);
		if (plen == (size_t)(-1))
			return 1;
	}

	if (optind < argc)
		return quick_usage (argv[0]);

	setvbuf (stdout, NULL, _IONBF, 0);
	return -traceroute (dsthost, dstport, srchost, srcport, wait, delay,
	                    retries, plen, minhlim, maxhlim);
}
