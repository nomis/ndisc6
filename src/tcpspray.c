/*
 * tcpspray.c - Address family independant complete rewrite of tcpspray
 * Plus, this file has a clear copyright statement.
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2006 Rémi Denis-Courmont.                              *
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
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <limits.h> // SIZE_MAX
#include <stdlib.h>

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include "gettime.h"
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
tcpspray (const char *host, const char *serv, unsigned long n, size_t blen,
          unsigned delay_us, const char *fillname, bool echo)
{
	if (serv == NULL)
		serv = echo ? "echo" : "discard";

	int fd = tcpconnect (host, serv);
	if (fd == -1)
		return -1;

	uint8_t block[blen];
	memset (block, 0, blen);

	if (fillname != NULL)
	{
		FILE *stream = fopen (fillname, "r");
		if (stream == NULL)
		{
			perror (fillname);
			close (fd);
			return -1;
		}

		size_t res = fread (block, 1, blen, stream);
		if (res < blen)
		{
			fprintf (stderr, _("Warning: \"%s\" is too small (%lu %s) "
			           "to fill block of %lu %s.\n"), fillname,
			         (unsigned long)res, ngettext ("byte", "bytes", res),
			         (unsigned long)blen, ngettext ("byte", "bytes", blen));
		}
		fclose (stream);
	}

	if (verbose)
	{
		printf (_("Sending %lu bytes with blocksize %u bytes\n"), n * blen,
		        blen);
	}

	if (echo)
	{
		switch (fork ())
		{
			case 0:
				for (unsigned i = 0; i < n; i++)
				{
					int val = recv (fd, block, blen, MSG_WAITALL);
					if (val != (int)blen)
					{
						fprintf (stderr, _("Cannot receive data: %s\n"),
								 (val == -1) ? strerror (errno)
							: _("Connection closed by peer"));
						exit (1);
					}

					if (verbose)
						fputs ("\b \b", stdout);
				}
				exit (0);

			case -1:
				perror ("fork");
				close (fd);
				return -1;
		}
	}
	else
		shutdown (fd, SHUT_RD);

	struct timespec delay_ts = { 0, 0 };
	if (delay_us)
	{
		div_t d = div (delay_us, 1000000);
		delay_ts.tv_sec = d.quot;
		delay_ts.tv_nsec = d.rem * 1000;
	}

	struct timespec start, end;
	gettime (&start);

	for (unsigned i = 0; i < n; i++)
	{
		int val = write (fd, block, blen);
		if (val != (int)blen)
		{
			fprintf (stderr, _("Cannot send data: %s\n"),
			         (val == -1) ? strerror (errno)
			                     : _("Connection closed by peer"));
			goto abort;
		}

		if (verbose)
			fputc ('.', stdout);

		if (delay_us && clock_nanosleep (CLOCK_MONOTONIC, 0, &delay_ts, NULL))
			goto abort;
	}

	gettime (&end);
	shutdown (fd, SHUT_WR);
	close (fd);

	if (echo)
	{
		int status;
		while (wait (&status) == -1);

		if (!WIFEXITED (status) || WEXITSTATUS (status))
		{
			fprintf (stderr, _("Child process returned an error"));
			return -1;
		}

		struct timespec end_recv;
		gettime (&end_recv);

		double rduration = ((double)end_recv.tv_sec)
		                 + ((double)end_recv.tv_nsec) / 1000000000;

		printf (_("Received %lu bytes in %f seconds"), n * blen, rduration);
		if (rduration > 0)
			printf (_(" (%0.3f kbytes/s)"),
			        ((double)blen) * n / rduration / 1024);
	}
	puts ("");

	double duration = ((double)end.tv_sec) + ((double)end.tv_nsec) / 1000000000;

	printf (_("Transmitted %lu bytes in %f seconds"), n * blen, duration);
	if (duration > 0)
		printf (_(" (%0.3f kbytes/s)"), ((double)blen) * n / duration / 1024);
	puts ("");

	return 0;

abort:
	close (fd);
	if (echo)
		while (wait (NULL) == -1);
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
"Usage: %s [options] <hostname/address> [service/port number]\n"
"Use the discard TCP service at the specified host\n"
"(the default host is the local system, the default service is discard)\n"),
	        path);

	puts (_("\n"
"  -4  force usage of the IPv4 protocols family\n"
"  -6  force usage of the IPv6 protocols family\n"
"  -b  specify the block bytes size (default: 1024)\n"
"  -d  wait for given delay (usec) between each block (default: 0)\n"
"  -e  perform a duplex test (TCP Echo instead of TCP Discard)\n"
"  -f  fill sent data blocks with the specified file content\n"
"  -h  display this help and exit\n"
"  -n  specify the number of blocks to send (default: 100)\n"
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
	{ "bsize",    required_argument, NULL, 'b' },
	{ "delay",    required_argument, NULL, 'd' },
	{ "echo",     no_argument,       NULL, 'e' },
	{ "file",     required_argument, NULL, 'f' },
	{ "fill",     required_argument, NULL, 'f' },
	{ "help",     no_argument,       NULL, 'h' },
	{ "count",    required_argument, NULL, 'n' },
	{ "version",  no_argument,       NULL, 'V' },
	{ "verbose",  no_argument,       NULL, 'v' },
	{ NULL,       0,                 NULL, 0   }
};

static const char optstr[] = "46b:d:ef:hn:Vv";

int main (int argc, char *argv[])
{
	unsigned long block_count = 100;
	size_t block_length = 1024;
	unsigned delay_ms = 0;
	bool echo = false;
	const char *fillname = NULL;

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

			case 'b':
			{
				char *end;
				unsigned long value = strtoul (optarg, &end, 0);
				if (*end)
					errno = EINVAL;
				else
				if (value > SIZE_MAX)
					errno = ERANGE;
				if (errno)
				{
					perror (optarg);
					return 2;
				}
				block_length = (size_t)value;
				break;
			}

			case 'd':
			{
				char *end;
				unsigned long value = strtoul (optarg, &end, 0);
				if (*end)
					errno = EINVAL;
				else
					if (value > UINT_MAX)
						errno = ERANGE;
				if (errno)
				{
					perror (optarg);
					return 2;
				}
				delay_ms = (unsigned)value;
				break;
			}

			case 'e':
				echo = true;
				break;

			case 'f':
				fillname = optarg;
				break;

			case 'h':
				return usage (argv[0]);

			case 'n':
			{
				char *end;
				block_count = strtoul (optarg, &end, 0);
				if (*end)
					errno = EINVAL;
				if (errno)
				{
					perror (optarg);
					return 2;
				}
				break;
			}

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

	if (optind >= argc)
		return quick_usage (argv[0]);

	const char *hostname = argv[optind++];
	const char *servname = (optind < argc) ? argv[optind++] : NULL;

	setvbuf (stdout, NULL, _IONBF, 0);
	c = tcpspray (hostname, servname, block_count, block_length,
	              delay_ms, fillname, echo);
	return c ? 1 : 0;
}
