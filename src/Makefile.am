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
mysuidexecdir = $(myexecdir)

AM_CPPFLAGS = -I$(top_srcdir) -DMYEXECDIR=\"$(myexecdir)\"

mysuidexec_PROGRAMS = ndisc6 rdisc6 rltraceroute6
myexec_PROGRAMS = tcptraceroute6
myexec_SCRIPTS = tracert6
bin_PROGRAMS = tcpspray6 addrinfo
bin_SCRIPTS = dnssort nameinfo
noinst_HEADERS = gettime.h inet6rth.h
EXTRA_DIST = dnssort.in

MOSTLYCLEANFILES = $(myexec_SCRIPTS) $(bin_SCRIPTS)

# ndisc6
ndisc6_SOURCES = ndisc.c
ndisc6_LDADD = $(LIBRT)

# rdisc6
rdisc6_SOURCES = ndisc.c
rdisc6_CFLAGS = -DRDISC
rdisc6_LDADD = $(LIBRT)

# traceroute6
rltraceroute6_SOURCES = traceroute.c traceroute.h \
			trace-tcp.c trace-udp.c trace-icmp.c
rltraceroute6_LDADD = $(LIBRT)

# tcptraceroute6
tcptraceroute6_SOURCES = tcptraceroute.c

#tcptraceroute6: Makefile.in $(top_builddir)/config.status
#	rm -f $@.tmp $@
#	echo '#! /bin/sh' > $@.tmp
#	echo 'exec "$$(dirname $$0)/rltraceroute6" -S "$$@"' >> $@.tmp
#	chmod +x $@.tmp
#	mv -f $@.tmp $@

tracert6: Makefile.in $(top_builddir)/config.status
	rm -f $@.tmp $@
	echo '#! /bin/sh' > $@.tmp
	echo 'exec "$$(dirname $$0)/rltraceroute6" -I "$$@"' >> $@.tmp
	chmod +x $@.tmp
	mv -f $@.tmp $@

# tcpspray6
tcpspray6_SOURCES = tcpspray.c
tcpspray6_LDADD = $(LIBRT)

nameinfo: Makefile.in $(top_builddir)/config.status
	rm -f $@.tmp $@
	echo '#! /bin/sh' > $@.tmp
	echo 'exec "$$(dirname $$0)/addrinfo" -r "$$@"' >> $@.tmp
	chmod +x $@.tmp
	mv -f $@.tmp $@

subst_script = sed \
	-e 's,[@]PERL[@],$(PERL),g' \
	-e 's,[@]PACKAGE[@],$(PACKAGE),g' \
	-e 's,[@]VERSION[@],$(VERSION),g'

# dnssort
dnssort: dnssort.in Makefile.in $(top_builddir)/config.status
	rm -f $@.tmp $@
	$(subst_script) < $(srcdir)/$@.in > $@.tmp
	chmod +x $@.tmp
	mv -f $@.tmp $@

if NOSUID
myexecdir = $(sbindir)
else
myexecdir = $(bindir)

install-exec-hook:
	@for f in $(mysuidexec_PROGRAMS); do \
		echo chmod u+s "$(DESTDIR)$(mysuidexecdir)/$$f" ; \
		chmod u+s "$(DESTDIR)$(mysuidexecdir)/$$f" || exit $$? ; \
	done
endif

