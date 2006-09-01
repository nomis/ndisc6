/*
 * trace-tcp.c - TCP support for IPv6 traceroute tool
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

#undef _GNU_SOURCE
#define _BSD_SOURCE 1

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
#include "gettime.h"
#ifndef SOL_IPV6
# define SOL_IPV6 IPPROTO_IPV6
#endif
#ifndef SOL_ICMPV6
# define SOL_ICMPV6 IPPROTO_ICMPV6
#endif

#include "traceroute.h"

#define TCP_WINDOW 4096

int tcpflags = 0;

/* TCP/SYN probes */
static int
send_syn_probe (int fd, unsigned ttl, unsigned n, size_t plen, uint16_t port)
{
	struct tcphdr th;

	memset (&th, 0, sizeof (th));
	th.th_sport = sport;
	th.th_dport = port;
	th.th_seq = htonl ((ttl << 24) | (n << 16) | getpid ());
	th.th_off = sizeof (th) / 4;
	th.th_flags = TH_SYN | tcpflags;
	th.th_win = htons (TCP_WINDOW);
	(void)plen; // FIXME

	return send_payload (fd, &th, sizeof (th));
}


static int
parse_syn_resp (const void *data, size_t len, unsigned *ttl, unsigned *n,
                uint16_t port)
{
	const struct tcphdr *pth = (const struct tcphdr *)data;
	uint32_t seq;

	if ((len < sizeof (*pth))
	 || (pth->th_dport != sport)
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
	 || (pth->th_sport != sport)
	 || (pth->th_dport != port))
		return -1;

	seq = ntohl (pth->th_seq);
	if ((seq & 0xffff) != (unsigned)getpid ())
		return -1;

	*ttl = seq >> 24;
	*n = (seq >> 16) & 0xff;
	return 0;
}


const tracetype syn_type =
	{ SOCK_STREAM, IPPROTO_TCP, 16,
	  send_syn_probe, parse_syn_resp, parse_syn_error };


/* TCP/ACK probes */
static int
send_ack_probe (int fd, unsigned ttl, unsigned n, size_t plen, uint16_t port)
{
	struct tcphdr th;

	memset (&th, 0, sizeof (th));
	th.th_sport = sport;
	th.th_dport = port;
	th.th_ack = htonl ((ttl << 24) | (n << 16) | getpid ());
	th.th_off = sizeof (th) / 4;
	th.th_flags = TH_ACK;
	th.th_win = htons (TCP_WINDOW);
	(void)plen; // FIXME

	return send_payload (fd, &th, sizeof (th));
}


static int
parse_ack_resp (const void *data, size_t len, unsigned *ttl, unsigned *n,
                uint16_t port)
{
	const struct tcphdr *pth = (const struct tcphdr *)data;
	uint32_t seq;

	if ((len < sizeof (*pth))
	 || (pth->th_dport != sport)
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
	 || (pth->th_sport != sport)
	 || (pth->th_dport != port))
		return -1;

	seq = ntohl (pth->th_ack);
	if ((seq & 0xffff) != (unsigned)getpid ())
		return -1;

	*ttl = seq >> 24;
	*n = (seq >> 16) & 0xff;
	return 0;
}


const tracetype ack_type =
	{ SOCK_STREAM, IPPROTO_TCP, 16,
	  send_ack_probe, parse_ack_resp, parse_ack_error };

