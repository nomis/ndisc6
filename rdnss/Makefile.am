# Makefile.am - rdnss/ directory Makefile for ndisc6

# Copyright © 2006-2007 Rémi Denis-Courmont
# This file is distributed under the same license as the ndisc6 package.

confdir = $(sysconfdir)/rdnssd
myrundir = $(localstatedir)/run/rdnssd

EXTRA_DIST += rdnss/merge-hook.in
CLEANFILES += $(conf_SCRIPTS)
AM_INSTALLCHECK_STD_OPTIONS_EXEMPT = merge-hook
sbin_PROGRAMS = rdnssd
conf_SCRIPTS = merge-hook

# rdnssd
rdnssd_SOURCES = rdnss/rdnssd.c rdnss/rdnssd.h \
	rdnss/icmp.c \
	rdnss/netlink.c
rdnssd_LDADD = $(LIBRT) libcompat.a

# merge-hook
merge-hook: rdnss/merge-hook.in config.status
	$(AM_V_at)rm -f -- $@.tmp $@
	$(sed_verbose)$(subst_script) < $(srcdir)/rdnss/$@.in > $@.tmp
	$(AM_V_at)chmod -- +x $@.tmp
	$(AM_V_at)mv -f -- $@.tmp $@

install-data-hook::
	$(install_sh) -d -- $(DESTDIR)$(myrundir)
	-chown -- nobody $(DESTDIR)$(myrundir)

uninstall-hook::
	-rmdir $(DESTDIR)$(myrundir)
