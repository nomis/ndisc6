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
#LD = ld
INSTALL = install -c
prefix = /usr/local


TARGETS = ndisc rdisc
VERSION = 0.1.0
DEFS = -DPACKAGE_VERSION=\"$(VERSION)\"
ndisc_DEFS =
rdisc_DEFS = -DRDISC

all: $(TARGETS)

$(TARGETS): %: ndisc.c
	$(CC) $(DEFS) $($*_DEFS) $(CFLAGS) $(LDFLAGS) -o $@ $<

install: all install-man
	for f in $(TARGETS); do \
		$(INSTALL) -m 04755 $$f $(DESTDIR)$(prefix)/bin/$$f || \
			exit $$? ; \
	done

install-strip: all install-man
	for f in $(TARGETS); do \
		$(INSTALL) -s -m 04755 $$f $(DESTDIR)$(prefix)/bin/$$f || \
			exit $$? ; \
	done

install-man:
	mkdir -p $(DESTDIR)$(prefix)/man/man8
	for f in $(TARGETS); do \
		$(INSTALL) -m 0644 $$f.8 $(DESTDIR)$(prefix)/man/man8/$$f.8 || \
			exit $$? ; \
	done

uninstall:
	rm -f $(TARGETS:%=$(DESTDIR)$(prefix)/bin/%) \
		$(TARGETS:%=$(DESTDIR)$(prefix)/man/man8/%.8)

clean:
	rm -f $(TARGETS)

dist:
	mkdir -v ndisc-$(VERSION)
	cp ndisc.c $(TARGETS:%=%.8) Makefile README ndisc-$(VERSION)/
	cp /usr/share/common-licenses/GPL-2 ndisc-$(VERSION)/COPYING
	tar c ndisc-$(VERSION) | bzip2 > ndisc-$(VERSION).tar.bz2
	rm -Rf ndisc-$(VERSION)

.PHONY: clean all install install-man install-strip

