/*
 * inet6_rth_add.c - inet6_rth_* replacement for Routing Header type 0
 * $Id$
 */

/***********************************************************************
 *  Copyright (C) 2006 Rémi Denis-Courmont.                            *
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

#ifndef HAVE_INET6_RTH_ADD

#include <inttypes.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define LINKAGE static inline

LINKAGE
socklen_t inet6_rth_space (int type, int segments)
{
	if ((type != 0) || (segments < 0) || (segments > 127))
		return 0;

	return 8 + (segments * 16);
}

LINKAGE
void *inet6_rth_init (void *bp, socklen_t bp_len, int type, int segments)
{
	socklen_t needlen;

	needlen = inet6_rth_space (type, segments);
	if ((needlen == 0) || (bp_len < needlen))
		return NULL;

	memset (bp, 0, needlen);
	((uint8_t *)bp)[1] = segments * 2; /* type 0 specific */
	((uint8_t *)bp)[2] = type;
	return bp;
}

LINKAGE
int inet6_rth_add (void *bp, const struct in6_addr *addr)
{
	if (((uint8_t *)bp)[2] != 0)
		return -1;

	memcpy (((uint8_t *)bp) + 8 + 16 * ((uint8_t *)bp)[3]++, addr, 16);
	return 0;
}

#endif /* ifndef HAVE_INET6_RTH_ADD */

#ifndef IPV6_RECVRTHDR
# if defined (__linux__)
#  define IPV6_RECVRTHDR 56
#  undef IPV6_RTHDR
#  define IPV6_RTHDR 57
# else
#  warning Routing Header support missing! Define IPV6_(RECV)RTHDR!
# endif
#endif
