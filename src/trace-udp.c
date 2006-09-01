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

#undef _GNU_SOURCE
#define _BSD_SOURCE 1

#include <string.h>
#include <stdbool.h>

#include <sys/socket.h> // SOCK_DGRAM
#include <netinet/in.h>
#include <netinet/udp.h>

#include "traceroute.h"


/* UDP probes (traditional traceroute) */
static int
send_udp_probe (int fd, unsigned ttl, unsigned n, size_t plen, uint16_t port)
{
	if (plen < sizeof (struct udphdr))
		plen = sizeof (struct udphdr);

	struct
	{
		struct udphdr uh;
		uint8_t payload[plen - sizeof (struct udphdr)];
	} packet;
	memset (&packet, 0, plen);

	(void)n;
	packet.uh.uh_sport = sport;
	packet.uh.uh_dport = htons (ntohs (port) + ttl);
	packet.uh.uh_ulen = htons (plen);
	/*if (plen > sizeof (struct udphdr))
		packet.payload[0] = (uint8_t)ttl;*/

	return send_payload (fd, &packet, plen);
}


static int
parse_udp_error (const void *data, size_t len, unsigned *ttl, unsigned *n,
                 uint16_t port)
{
	const struct udphdr *puh = (const struct udphdr *)data;
	uint16_t rport;

	if ((len < 4) || (puh->uh_sport != sport ))
		return -1;

	rport = ntohs (puh->uh_dport);
	port = ntohs (port);
	if ((rport < port) || (rport > port + 255))
		return -1;

	*ttl = rport - port;
	*n = (unsigned)(-1);
	return 0;
}


const tracetype udp_type =
	{ SOCK_DGRAM, IPPROTO_UDP, 6,
	  send_udp_probe, NULL, parse_udp_error };
