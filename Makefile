#!/usr/bin/make -f
# Makefile - Makefile for ndisc
# $Id$

# ***********************************************************************
# *  Copyright (C) 2004 Remi Denis-Courmont.                            *
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
CFLAGS = -Wall -g
LDFLAGS =
#LD = ld
INSTALL = install -c
prefix = /usr/local

TARGETS = ndisc rdisc

all: $(TARGETS)

ndisc: ndisc.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

rdisc: ndisc.c
	$(CC) -DRDISC $(CFLAGS) $(LDFLAGS) -o $@ $<

install: all install-man
	$(INSTALL) -m 04755 ndisc $(DESTDIR)$(prefix)/bin/ndisc

install-strip: all install-man
	$(INSTALL) -s -m 04755 ndisc $(DESTDIR)$(prefix)/bin/ndisc

install-man:
	mkdir -p $(DESTDIR)$(prefix)/man/man8
	$(INSTALL) -m 0644 ndisc.8 $(DESTDIR)$(prefix)/man/man8/

uninstall:
	rm -f $(DESTDIR)$(prefix)/bin/ndisc

clean:
	rm -f $(TARGETS)

dist:
	mkdir -v ndisc-0.0.1
	cp ndisc.c ndisc.8 Makefile ndisc-0.0.1/
	tar c ndisc-0.0.1 > ndisc-0.0.1.tar
	bzip2 ndisc-0.0.1.tar
	rm -Rf ndisc-0.0.1

.PHONY: clean all install install-man install-strip

