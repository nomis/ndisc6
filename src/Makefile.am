# Makefile.am - src/ directory Makefile for ndisc6
# $Id$

# Copyright © 2006 Rémi Denis-Courmont
# This file is distributed under the same license as the ndisc6 package.

bindir = @bindir@
sbindir = @sbindir@
mysuidexecdir = $(myexecdir)

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/include \
	-DLOCALEDIR=\"$(localedir)\"

mysuidexec_PROGRAMS = ndisc6 rdisc6 rltraceroute6
myexec_PROGRAMS = tcptraceroute6
myexec_SCRIPTS = tracert6
bin_PROGRAMS = tcpspray addr2name
bin_SCRIPTS = tcpspray6 dnssort name2addr
sbin_PROGRAMS = rdnssd
noinst_HEADERS = gettime.h inet6rth.h
dist_noinst_SCRIPTS = gen-alias
EXTRA_DIST = dnssort.in
MOSTLYCLEANFILES = $(myexec_SCRIPTS) $(bin_SCRIPTS)

gen_alias = transform="$(transform)" ${SHELL} $(srcdir)/gen-alias

# ndisc6
ndisc6_SOURCES = ndisc.c
ndisc6_LDADD = $(LIBRT)

# rdisc6
rdisc6_SOURCES = ndisc.c
rdisc6_CPPFLAGS = -DRDISC $(AM_CPPFLAGS)
rdisc6_LDADD = $(LIBRT)

# rdnssd
rdnssd_SOURCES = rdnssd.c
rdnssd_LDADD = $(LIBRT)

# traceroute6
rltraceroute6_SOURCES = traceroute.c traceroute.h \
			trace-tcp.c trace-udp.c trace-icmp.c
rltraceroute6_LDADD = $(LIBRT)
tcptraceroute6_SOURCES = tcptraceroute.c
tcptraceroute6_CPPFLAGS = $(AM_CPPFLAGS) \
	-DRLTRACEROUTE6=\"`echo rltraceroute6 | sed '$(transform)'`\"

tracert6: Makefile.am gen-alias
	$(gen_alias) tracert6 rltraceroute6 -I

# tcpspray
tcpspray_SOURCES = tcpspray.c
tcpspray_LDADD = $(LIBRT)

tcpspray6: Makefile.am gen-alias
	$(gen_alias) tcpspray6 tcpspray -6

# addr2name
addr2name_SOURCES = addrinfo.c
name2addr: Makefile.am gen-alias
	$(gen_alias) name2addr addr2name -r

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
		i="`echo "$$f" | sed -e '$(program)'`" ; \
		echo chmod u+s "$(DESTDIR)$(mysuidexecdir)/$$i" ; \
		chmod u+s "$(DESTDIR)$(mysuidexecdir)/$$i" || exit $$? ; \
	done
endif

