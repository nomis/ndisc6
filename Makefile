#!/usr/bin/make -f
# Makefile - Makefile for ndisc
# $Id$

# ***********************************************************************
# *  Copyright (C) 2004-2005 Remi Denis-Courmont.                       *
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

CC = gcc
CFLAGS = -O2 -Wall -g
LDFLAGS =
#LINK = $(CC)
INSTALL = install -c
prefix = /usr/local

PACKAGE = ndisc6
VERSION = 0.4.1

sbin_PROGRAMS = ndisc6 rdisc6
DOC = COPYING NEWS README

AM_CPPFLAGS = -DPACKAGE_VERSION=\"$(VERSION)\"
ndisc6_CPPFLAGS = $(AM_CPPFLAGS)
rdisc6_CPPFLAGS = -DRDISC $(AM_CPPFLAGS)

all: $(sbin_PROGRAMS) $(DOC)

$(sbin_PROGRAMS): %: ndisc.c Makefile
	$(CC) $($*_CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $<

COPYING: /usr/share/common-licenses/GPL-2
	ln -s $< $@

install: all install-man
	mkdir -p $(DESTDIR)$(prefix)/bin
	for f in $(sbin_PROGRAMS); do \
		$(INSTALL) -m 04755 $$f $(DESTDIR)$(prefix)/bin/$$f || \
			exit $$? ; \
	done

install-strip: all install-man
	mkdir -p $(DESTDIR)$(prefix)/bin
	for f in $(sbin_PROGRAMS); do \
		$(INSTALL) -s -m 04755 $$f $(DESTDIR)$(prefix)/bin/$$f || \
			exit $$? ; \
	done

install-man:
	mkdir -p $(DESTDIR)$(prefix)/man/man8
	for f in $(sbin_PROGRAMS); do \
		$(INSTALL) -m 0644 $$f.8 $(DESTDIR)$(prefix)/man/man8/$$f.8 || \
			exit $$? ; \
	done

uninstall:
	rm -f $(sbin_PROGRAMS:%=$(DESTDIR)$(prefix)/bin/%) \
		$(sbin_PROGRAMS:%=$(DESTDIR)$(prefix)/man/man8/%.8)

mostlyclean:
	rm -f $(sbin_PROGRAMS)

clean: mostlyclean

distclean: clean

dist:
	mkdir -v $(PACKAGE)-$(VERSION)
	cp ndisc.c $(sbin_PROGRAMS:%=%.8) Makefile $(DOC) $(PACKAGE)-$(VERSION)/
	svn -v log > $(PACKAGE)-$(VERSION)/ChangeLog
	tar c $(PACKAGE)-$(VERSION) | bzip2 > $(PACKAGE)-$(VERSION).tar.bz2
	rm -Rf $(PACKAGE)-$(VERSION)

.PHONY: clean mostlyclean distclean all install install-man install-strip

