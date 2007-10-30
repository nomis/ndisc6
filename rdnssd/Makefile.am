# Makefile.am - rdnssd/ directory Makefile for ndisc6
# $Id$

# Copyright © 2006-2007 Rémi Denis-Courmont
# This file is distributed under the same license as the ndisc6 package.

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/include \
	-DLOCALEDIR=\"$(localedir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\"
confdir = $(sysconfdir)/$(PACKAGE)

subst_script = sed \
	-e 's,[@]PERL[@],$(PERL),g' \
	-e 's,[@]PACKAGE[@],$(PACKAGE),g' \
	-e 's,[@]VERSION[@],$(VERSION),g' \
	-e 's,[@]LOCALSTATEDIR[@],$(localstatedir),g'

EXTRA_DIST = merge-hook.in
sbin_PROGRAMS = rdnssd
conf_SCRIPTS = merge-hook

# rdnssd
rdnssd_SOURCES = rdnssd.c
rdnssd_LDADD = $(LIBRT)

# merge-hook
merge-hook: merge-hook.in Makefile.in $(top_builddir)/config.status
	rm -f $@.tmp $@
	$(subst_script) < $(srcdir)/$@.in > $@.tmp
	chmod +x $@.tmp
	mv -f $@.tmp $@

