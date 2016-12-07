# Makefile.am - master Makefile for ndisc6

# Copyright © 2006 Rémi Denis-Courmont
# This file is distributed under the same license as the ndisc6 package.

ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = \
	1.11 \
	check-news \
	dist-bzip2 \
	no-dist-gzip \
	no-exeext \
	std-options \
	subdir-objects \
	-Wall

EXTRA_DIST =
DISTCLEANFILES = stamp-git
CLEANFILES =
MOSTLYCLEANFILES =

AM_CPPFLAGS = -I$(top_srcdir)/include \
	-DLOCALEDIR=\"$(localedir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\"
AM_LIBADD = libcompat.a

noinst_HEADERS = include/gettext.h

sed_verbose = $(sed_verbose_$(V))
sed_verbose_ = $(sed_verbose_$(AM_DEFAULT_VERBOSITY))
sed_verbose_0 = @echo "  SED      $@";

subst_script = sed \
	-e 's,[@]LOCALSTATEDIR[@],$(localstatedir),g' \
	-e 's,[@]SYSCONFDIR[@],$(sysconfdir),g' \
	-e 's,[@]PERL[@],$(PERL),g' \
	-e 's,[@]PACKAGE[@],$(PACKAGE),g' \
	-e 's,[@]VERSION[@],$(VERSION),g'

include m4/Makefile.am
include doc/Makefile.am
include compat/Makefile.am
include src/Makefile.am
include rdnss/Makefile.am

SUBDIRS = po

distclean-local:
	test "$(top_srcdir)" = "$(top_builddir)" || rm -f ChangeLog

dist-hook: stamp-git

stamp-git:
	@LANG=C ; \
	rev=$$(cd "$(scrdir)" && git describe || echo exported) ; \
	oldrev=$$(cat stamp-git 2>/dev/null || true) ; \
	if test "$$rev" != "$$oldrev"; then \
		echo "New revision is: $$rev" ; \
		if test "$$rev" != "exported"; then \
			echo -n "Rebuilding ChangeLog... " ; \
			(cd "$(srcdir)" && git log) > ChangeLog || exit $$? ; \
			echo "OK" ; \
		fi ; \
	fi
	echo "$$rev" > stamp-git

ChangeLog:
	$(MAKE) $(AM_MAKEFLAGS) stamp-git
	touch $@

.PHONY: stamp-git
