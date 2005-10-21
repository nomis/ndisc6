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
CPPFLAGS =
#LINK = $(CC)
INSTALL = install -c
prefix = /usr/local

PACKAGE = ndisc6
VERSION = 0.5.1

sbin_PROGRAMS = ndisc6 rdisc6 traceroute6
man8_MANS = $(sbin_PROGRAMS:%=%.8)
DOC = COPYING INSTALL NEWS README

AM_CPPFLAGS = -DPACKAGE_VERSION=\"$(VERSION)\" $(CPPFLAGS)
ndisc6_CPPFLAGS = $(AM_CPPFLAGS)
rdisc6_CPPFLAGS = -DRDISC $(AM_CPPFLAGS)
traceroute6_CPPFLAGS = $(AM_CPPFLAGS)

all: $(sbin_PROGRAMS) $(DOC) tcptraceroute6

ndisc6 rdisc6: %: ndisc.c Makefile
	$(CC) $($*_CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $<

traceroute6: %: traceroute.c Makefile
	$(CC) $($*_CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $<

tcptraceroute6: traceroute6
	ln -s traceroute6 $@

COPYING: /usr/share/common-licenses/GPL-2
	ln -s $< $@

install: all install-man install-links
	mkdir -p $(DESTDIR)$(prefix)/bin
	for f in $(sbin_PROGRAMS); do \
		$(INSTALL) -m 04755 $$f $(DESTDIR)$(prefix)/bin/$$f || \
			exit $$? ; \
	done

install-strip: all install-man install-links
	mkdir -p $(DESTDIR)$(prefix)/bin
	for f in $(sbin_PROGRAMS); do \
		$(INSTALL) -s -m 04755 $$f $(DESTDIR)$(prefix)/bin/$$f || \
			exit $$? ; \
	done

install-man:
	mkdir -p $(DESTDIR)$(prefix)/man/man8
	for f in $(man8_MANS); do \
		$(INSTALL) -m 0644 $$f $(DESTDIR)$(prefix)/man/man8/$$f || \
			exit $$? ; \
	done
	cd $(DESTDIR)$(prefix)/man/man8 && \
	ln -sf traceroute6.8 tcptraceroute6.8

install-links:
	cd $(DESTDIR)$(prefix)/bin && ln -sf traceroute6 tcptraceroute6

uninstall:
	rm -f $(sbin_PROGRAMS:%=$(DESTDIR)$(prefix)/bin/%)
	rm -f $(man8_MANS:%=$(DESTDIR)$(prefix)/man/man8/%)
	rm -f $(DESTDIR)$(prefix)/bin/tcptraceroute6
	rm -f $(DESTDIR)$(prefix)/man/man8/tcptraceroute6.8

mostlyclean:
	rm -f $(sbin_PROGRAMS) tcptraceroute6

clean: mostlyclean
	rm -f *~

distclean: clean

dist:
	mkdir -v $(PACKAGE)-$(VERSION)
	cp ndisc.c traceroute.c $(sbin_PROGRAMS:%=%.8) Makefile $(DOC) \
		$(PACKAGE)-$(VERSION)/
	svn -v log > $(PACKAGE)-$(VERSION)/ChangeLog
	tar c $(PACKAGE)-$(VERSION) | bzip2 > $(PACKAGE)-$(VERSION).tar.bz2
	rm -Rf $(PACKAGE)-$(VERSION)

.PHONY: clean mostlyclean distclean all install install-man install-strip

