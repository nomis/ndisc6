/*
 * tcpspray.c - Address family independant complete rewrite of tcpspray
 * Plus, this file has a clear copyright statement.
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>

static int family = 0;
static int verbose = 0;

static int tcpconnect (const char *host, const char *serv)
{
	struct addrinfo hints, *res;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	int val = getaddrinfo (host, serv, &hints, &res);
	if (val)
	{
		fprintf (stderr, _("%s port %s: %s\n"), host, serv,
		         gai_strerror (val));
		return -1;
	}

	val = -1;

	for (struct addrinfo *p = res; (p != NULL) && (val == -1); p = p->ai_next)
	{
		val = socket (p->ai_family, p->ai_socktype, p->ai_protocol);
		if (val == -1)
		{
			perror ("socket");
			continue;
		}

		int yes = 1;
		setsockopt (val, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (yes));
		fcntl (val, F_SETFD, FD_CLOEXEC);

		if (connect (val, p->ai_addr, p->ai_addrlen))
		{
			fprintf (stderr, _("%s port %s: %s\n"), host, serv,
			         strerror (errno));
			close (val);
			val = -1;
			continue;
		}
	}

	freeaddrinfo (res);
	return val;
}


static int
tcpspray (const char *host, unsigned n, size_t blen)
{
	int fd = tcpconnect (host, "discard");
	if (fd == -1)
		return -1;

	uint8_t block[blen];
	memset (block, 0, blen);

	struct timeval start, end;
	gettimeofday (&start, NULL);

	for (unsigned i = 0; i < n; i++)
	{
		if (write (fd, block, blen) != (int)blen)
		{
			perror (_("Cannot send data"));
			goto abort;
		}

		if (verbose)
			fputc ('.', stdout);
	}

	gettimeofday (&end, NULL);
	close (fd);

	puts ("");
	if (end.tv_sec < start.tv_sec)
		goto backward;

	end.tv_sec -= start.tv_sec;
	if (end.tv_usec < start.tv_usec)
	{
		if (end.tv_sec <= 0)
			goto backward;
		end.tv_sec--;
		end.tv_usec += 1000000;
	}
	end.tv_usec -= start.tv_usec;

	double duration = ((double)end.tv_sec) + ((double)end.tv_usec) / 1000000;

	printf (_("Transmitted %lu bytes in %f seconds"),
	        (unsigned long)blen * n, duration);
	if (duration == 0.)
	{
		puts ("");
		return 0;
	}

	printf (_(" (%0.3f kbytes/s)\n"), ((double)blen) * n / duration / 1024);
	return 0;

backward:
	// This can actually happen if the system clock was NTP'd.
	fputs (_("Clock went back in time. Aborting.\n"), stderr);
	return -1;

abort:
	close (fd);
	return -1;
}


/* TODO:
-b block byte size (default 1024)
-d optional microseconds delay between each block
-e echo service instead of discard
-f load block content from file (all zeroes by default)
-h help
-n blocks count (default 100)
-v verbose
 * also: -4, -6, service specification
 */


int main (int argc, char *argv[])
{
	unsigned block_count = 100;
	size_t block_length = 1024;

	if (argc < 2)
		return 1;
	if (!strcmp (argv[1], "--version"))
	{
		puts ("tcpspray6 preversion "VERSION);
		return 0;
	}
	if (!strcmp (argv[1], "--help"))
	{
		puts ("Usage: tcpspray6 <hostname>");
		return 0;
	}

	setvbuf (stdout, NULL, _IONBF, 0);
	if (verbose)
		printf (_("Sending %lu bytes with blocksize %u bytes\n"),
		        ((unsigned long)block_length) * block_count, block_length);

	return -tcpspray (argv[1], block_count, block_length);
}
