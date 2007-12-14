# Makefile.am - doc Makefile for ndisc6
# $Id$

# Copyright © 2006-2007 Rémi Denis-Courmont
# This file is distributed under the same license as the ndisc6 package.

man1_MANS = addr2name.1 dnssort.1 tcpspray.1
man8_MANS = ndisc6.8 rdisc6.8 rltraceroute6.8

EXTRA_DIST = $(man1_MANS) $(man8_MANS)

# Make sure manpages are plain ASCII
distcheck-hook:
	cd "$(srcdir)" && \
	cat $(man1_MANS) $(man8_MANS) | grep -ve '\.\\"' | \
		iconv -f ASCII >/dev/null
