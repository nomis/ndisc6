# Makefile.am - master Makefile for ndisc6
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

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src
DIST_SUBDIRS = m4 $(SUBDIRS)
man1_MANS = doc/addrinfo.1 doc/dnssort.1 doc/tcpspray.1
man8_MANS = doc/ndisc6.8 doc/rdisc6.8 doc/rltraceroute6.8

EXTRA_DIST = $(man1_MANS) $(man8_MANS)
DISTCLEANFILES = stamp-svn

install-data-hook:
	inst=`echo rltraceroute6 | sed '$(transform)'`; \
	for a in tcptraceroute6 tracert6; do \
		ln -sf "$(man8dir)/$${inst}.8" \
			"$(DESTDIR)$(man8dir)/$$a.8" ; \
	done
	inst=`echo tcpspray | sed '$(transform)'`; \
	for a in 4 6; do \
		ln -sf "$(man1dir)/$${inst}.1" \
			"$(DESTDIR)$(man1dir)/tcpspray$$a.1" ; \
	done
	inst=`echo addrinfo | sed '$(transform)'`; \
	ln -sf "$(man1dir)/$${inst}.1" \
		"$(DESTDIR)$(man1dir)/nameinfo.1"

uninstall-hook:
	for a in tcptraceroute6 tracert6; do \
		rm -f "$(DESTDIR)$(man8dir)/$$a.8" ; \
	done
	for a in 4 6; do \
		rm -f "$(DESTDIR)$(man1dir)/tcpspray$$a.1" ; \
	done
	unlink "$(DESTDIR)$(man1dir)/nameinfo.1"

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
