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

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/select.h> /* select() */
#include <sys/socket.h>
#include <unistd.h> /* close() */
#include <sys/ioctl.h>

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
ndisc (const char *name, const char *ifname)
{
	struct in6_addr tgt;
	struct timeval tv;

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
		printf ("Looking up %s (%s) on %s...\n", name, s, ifname);
	}

	/* sends a Neigbor Solitication */
	if (sendns (fd, &tgt, ifname))
	{
		close (fd);
		return -1;
	}

	/* waits at most 3 seconds for positive reply */
	tv.tv_sec = 3;
	tv.tv_usec = 0;
	do
	{
		struct
		{
			struct nd_neighbor_advert adv;
			struct nd_opt_hdr ohdr;
			uint8_t hw_addr[6];
		} na;
		int val;
		fd_set set;

		/* waits for reply for at most 3 seconds */
		FD_ZERO (&set);
		FD_SET (fd, &set);

		/* NOTE: Linux-like semantics assumed for select() */
		val = select (fd + 1, &set, NULL, NULL, &tv);
		switch (val)
		{
			case 0:
				puts ("No response.");
				close (fd);
				return -1;

			case -1:
				perror ("select");
				close (fd);
				return -1;
		}

		val = recvfrom (fd, &na, sizeof (na), 0, NULL, 0);
		if (val != sizeof (na))
			continue;

		if (na.adv.nd_na_type == ND_NEIGHBOR_ADVERT
		 && !memcmp (&na.adv.nd_na_target, &tgt, 16))
		{
			printf ("Source link-layer address: "
				"%02X:%02X:%02X:%02X:%02X:%02X\n",
				na.hw_addr[0], na.hw_addr[1],
				na.hw_addr[2], na.hw_addr[3],
				na.hw_addr[4], na.hw_addr[5]);
			close (fd);
			fd = -1;
		}	
	}
	while (fd != -1);

	return 0;
}


int
main (int argc, char *argv[])
{
	if (argc != 3)
	{
		fputs ("Usage: ndisc <IPv6 address> <interface>\n", stderr);
		return 1;
	}

	return ndisc (argv[1], argv[2]) ? 2 : 0;
}

