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
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

static int family = 0;
static unsigned verbose = 0;

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
		fprintf (stderr, _("%s port %s: %s\n"),
		         (host != NULL) ? host : _("local system"), serv,
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
			fprintf (stderr, _("%s port %s: %s\n"),
			         (host != NULL) ? host : _("local system"), serv,
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
tcpspray (const char *host, const char *serv, unsigned long n, size_t blen)
{
	int fd = tcpconnect (host, serv);
	if (fd == -1)
		return -1;

	uint8_t block[blen];
	memset (block, 0, blen);

	if (verbose)
	{
		printf (_("Sending %lu bytes with blocksize %u bytes\n"), n * blen,
		        blen);
	}

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

	printf (_("Transmitted %lu bytes in %f seconds"), n * blen, duration);
	if (duration > 0)
		printf (_(" (%0.3f kbytes/s)"), ((double)blen) * n / duration / 1024);
	puts ("");

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
-n blocks count (default 100)
 */

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
"Usage: %s [options] [hostname/address] [service/port number]\n"
"Use the discard TCP service at the specified host\n"
"(the default host is the local system, the default service is discard)\n"),
	        path);

	puts (_("\n"
"  -4  force usage of the IPv4 protocols family\n"
"  -6  force usage of the IPv6 protocols family\n"
//"  -b  specify the block bytes size (default: 1024)\n"
"  -h  display this help and exit\n"
"  -V  display program version and exit\n"
"  -v  enable verbose output\n"
	));

	return 0;
}


static int
version (void)
{
	printf (_(
"tcpspray6: TCP/IP bandwidth tester %s ($Rev$)\n"
" built %s on %s\n"), VERSION, __DATE__, PACKAGE_BUILD_HOSTNAME);
	printf (_("Configured with: %s\n"), PACKAGE_CONFIGURE_INVOCATION);
	puts (_("Written by Remi Denis-Courmont\n"));

	printf (_("Copyright (C) %u-%u Remi Denis-Courmont\n"
"This is free software; see the source for copying conditions.\n"
"There is NO warranty; not even for MERCHANTABILITY or\n"
"FITNESS FOR A PARTICULAR PURPOSE.\n"), 2005, 2006);
	return 0;
}


static const struct option opts[] =
{
	{ "ipv4",     no_argument,       NULL, '4' },
	{ "ipv6",     no_argument,       NULL, '6' },
//	{ "echo",     no_argument,       NULL, 'e' },
	{ "help",     no_argument,       NULL, 'h' },
	{ "version",  no_argument,       NULL, 'V' },
	{ "verbose",  no_argument,       NULL, 'v' },
	{ NULL,       0,                 NULL, 0   }
};

static const char optstr[] = "46hVv";

int main (int argc, char *argv[])
{
	unsigned long block_count = 100;
	size_t block_length = 1024;

	int c;
	while ((c = getopt_long (argc, argv, optstr, opts, NULL)) != EOF)
	{
		switch (c)
		{
			case '4':
				family = AF_INET;
				break;

			case '6':
				family = AF_INET6;
				break;

			case 'h':
				return usage (argv[0]);

			case 'V':
				return version ();

			case 'v':
				if (verbose < UINT_MAX)
					verbose++;
				break;

			case '?':
			default:
				return quick_usage (argv[0]);
		}
	}

	const char *hostname = NULL, *servname = "discard";
	if (optind < argc)
	{
		hostname = argv[optind++];
		if (optind < argc)
			servname = argv[optind++];
	}

	setvbuf (stdout, NULL, _IONBF, 0);
	return -tcpspray (hostname, servname, block_count, block_length);
}
