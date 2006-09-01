/*
 * traceroute.h - TCP/IPv6 traceroute tool common header
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

#ifndef NDISC6_TRACEROUTE_H
# define NDISC6_TRACEROUTE_H

typedef struct tracetype
{
	int gai_socktype;
	int protocol;
	int checksum_offset;
	int (*send_probe) (int fd, unsigned ttl, unsigned n, size_t plen,
	                   uint16_t port);
	int (*parse_resp) (const void *data, size_t len, unsigned *ttl,
	                   unsigned *n, uint16_t port);
	int (*parse_err) (const void *data, size_t len, unsigned *ttl,
	                  unsigned *n, uint16_t port);
} tracetype;

# ifdef __cplusplus
extern "C" {
# endif

int send_payload (int fd, const void *payload, size_t length);

# ifdef __cplusplus
}
#endif

extern bool ecn;
extern uint16_t sport;

extern const tracetype udp_type, echo_type, syn_type, ack_type;

#endif
