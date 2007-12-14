# Makefile.am - master Makefile for ndisc6
# $Id$

# Copyright © 2006 Rémi Denis-Courmont
# This file is distributed under the same license as the ndisc6 package.

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = po doc src rdnssd
DIST_SUBDIRS = m4 $(SUBDIRS)
noinst_HEADERS = include/gettext.h

DISTCLEANFILES = stamp-svn

install-data-hook:
	inst=`echo rltraceroute6 | sed '$(transform)'`; \
	for a in tcptraceroute6 tracert6; do \
		ln -sf "$(man8dir)/$${inst}.8" \
			"$(DESTDIR)$(man8dir)/$$a.8" ; \
	done
	inst=`echo tcpspray | sed '$(transform)'`; \
	ln -sf "$(man1dir)/$${inst}.1" \
		"$(DESTDIR)$(man1dir)/tcpspray6.1"
	inst=`echo addr2name | sed '$(transform)'`; \
	ln -sf "$(man1dir)/$${inst}.1" \
		"$(DESTDIR)$(man1dir)/name2addr.1"

uninstall-hook:
	for a in tcptraceroute6 tracert6; do \
		unlink "$(DESTDIR)$(man8dir)/$$a.8" ; \
	done
	unlink "$(DESTDIR)$(man1dir)/tcpspray6.1"
	unlink "$(DESTDIR)$(man1dir)/name2addr.1"

distcheck-hook:
	cd doc && $(MAKE) $(AM_MAKEFLAGS) distcheck-hook

distclean-local:
	test "$(top_srcdir)" = "$(top_builddir)" || rm -f ChangeLog

dist-hook: stamp-svn

stamp-svn:
	@rev=$$(LANG=C svnversion "$(srcdir)" 2>/dev/null || echo exported) ; \
	oldrev=$$(cat stamp-svn 2>/dev/null || true) ; \
	if test "$$rev" != "$$oldrev"; then \
		echo "New SVN revision is $$rev." ; \
		if test "$$rev" != "exported"; then \
			echo -n "Rebuilding ChangeLog... " ; \
			LANG=C svn -v --non-interactive log "$(srcdir)" > ChangeLog || exit $$? ; \
			echo "OK" ; \
		fi ; \
		echo "$$rev" > $@ ; \
	fi

ChangeLog:
	$(MAKE) $(AM_MAKEFLAGS) stamp-svn
	touch $@

.PHONY: stamp-svn
