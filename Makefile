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

TARGETS = ndisc

all: $(TARGETS)

$(TARGETS): %: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

install: all
	$(INSTALL) -m 04755 ndisc $(DESTDIR)$(prefix)/bin/ndisc

install-strip: all
	$(INSTALL) -s -m 04755 ndisc $(DESTDIR)$(prefix)/bin/ndisc

uninstall:
	rm -f $(DESTDIR)$(prefix)/bin/ndisc

clean:
	rm -f $(TARGETS)

.PHONY: clean all install

