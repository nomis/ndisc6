# Makefile.am - doc Makefile for ndisc6

# Copyright © 2006-2007 Rémi Denis-Courmont
# This file is distributed under the same license as the ndisc6 package.

man1_MANS = doc/addr2name.1 doc/dnssort.1 doc/tcpspray.1
man8_MANS = doc/ndisc6.8 doc/rdisc6.8 doc/rltraceroute6.8 doc/rdnssd.8
SOURCES_MAN = \
	doc/ndisc6.8 doc/rdisc6.8 \
	doc/rltraceroute6.8 \
	doc/rdnssd.8-in \
	$(man1_MANS)

EXTRA_DIST += $(SOURCES_MAN)
CLEANFILES += doc/rdnssd.8

edit = sed \
	-e 's,@localstatedir\@,$(localstatedir),g' \
	-e 's,@sysconfdir\@,$(sysconfdir),g'

.8-in.8:
	$(AM_V_at)rm -f -- $@
	$(AM_V_at)mkdir -p doc
	$(sed_verbose)$(edit) $< > $@

install-data-hook::
	inst=`echo rltraceroute6 | sed '$(transform)'`; \
	cd "$(DESTDIR)$(man8dir)" && \
	for a in tcptraceroute6 tracert6; do \
		ln -sf -- "$${inst}.8" "$$a.8" ; \
	done
	inst=`echo tcpspray | sed '$(transform)'`; \
	cd "$(DESTDIR)$(man1dir)" && \
	ln -sf -- "$${inst}.1" "tcpspray6.1"
	inst=`echo addr2name | sed '$(transform)'`; \
	cd "$(DESTDIR)$(man1dir)" && \
	ln -sf -- "$${inst}.1" "name2addr.1"

uninstall-hook::
	for a in tcptraceroute6 tracert6; do \
		unlink "$(DESTDIR)$(man8dir)/$$a.8" ; \
	done
	unlink "$(DESTDIR)$(man1dir)/tcpspray6.1"
	unlink "$(DESTDIR)$(man1dir)/name2addr.1"
