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
	-Wall

SUBDIRS = po doc compat src rdnssd
DIST_SUBDIRS = m4 $(SUBDIRS)
noinst_HEADERS = include/gettext.h

DISTCLEANFILES = stamp-git

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
