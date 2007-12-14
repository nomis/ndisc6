# Makefile.am - doc Makefile for ndisc6
# $Id$

# Copyright © 2006-2007 Rémi Denis-Courmont
# This file is distributed under the same license as the ndisc6 package.

man1_MANS = addr2name.1 dnssort.1 tcpspray.1
man8_MANS = ndisc6.8 rdisc6.8 rltraceroute6.8

EXTRA_DIST = $(man1_MANS) $(man8_MANS)

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

# Make sure manpages are plain ASCII
distcheck-hook:
	cd "$(srcdir)" && \
	cat $(man1_MANS) $(man8_MANS) | grep -ve '\.\\"' | \
		iconv -f ASCII >/dev/null
