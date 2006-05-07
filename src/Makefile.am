# Makefile.am - src/ directory Makefile for ndisc6
# $Id$

# ***********************************************************************
# *  Copyright © 2006 Rémi Denis-Courmont.                              *
# *  This program is free software; you can redistribute and/or modify  *
# *  it under the terms of the GNU General Public License as published  *
# *  by the Free Software Foundation; version 2 of the license.         *
# *                                                                     *
# *  This program is distributed in the hope that it will be useful,    *
# *  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
# *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.               *
# *  See the GNU General Public License for more details.               *
# *                                                                     *
# *  You should have received a copy of the GNU General Public License  *
# *  along with this program; if not, you can get it from:              *
# *  http://www.gnu.org/copyleft/gpl.html                               *
# ***********************************************************************

bindir = @bindir@
sbindir = @sbindir@

AM_CPPFLAGS = -I$(top_srcdir) -D_BSD_SOURCE
AM_CFLAGS = -std=gnu99

myexec_PROGRAMS = ndisc6 rdisc6 traceroute6
myexec_SCRIPTS = tcptraceroute6 tracert6
bin_PROGRAMS = tcpspray6

MOSTLYCLEANFILES = $(myexec_SCRIPTS)

# ndisc6
ndisc6_SOURCES = ndisc.c

# rdisc6
rdisc6_SOURCES = ndisc.c
rdisc6_CFLAGS = -DRDISC

# traceroute6
traceroute6_SOURCES = traceroute.c

tcptraceroute6: Makefile.in $(top_builddir)/config.status
	rm -f $@.tmp $@
	echo '#! /bin/sh' > $@.tmp
	echo 'exec $(myexecdir)/traceroute6 -S "$$@"' >> $@.tmp
	chmod +x $@.tmp
	mv -f $@.tmp $@

tracert6: Makefile.in $(top_builddir)/config.status
	rm -f $@.tmp $@
	echo '#! /bin/sh' > $@.tmp
	echo 'exec $(myexecdir)/traceroute6 -I "$$@"' >> $@.tmp
	chmod +x $@.tmp
	mv -f $@.tmp $@

# tcpspray6
tcpspray6_SOURCES = tcpspray.c

if NOSUID
myexecdir = $(sbindir)
else
myexecdir = $(bindir)

install-exec-hook:
	@for f in $(myexec_PROGRAMS); do \
		echo chmod u+s "$(DESTDIR)$(myexecdir)/$$f" ; \
		chmod u+s "$(DESTDIR)$(myexecdir)/$$f" || exit $$? ; \
	done
endif
