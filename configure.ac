dnl configure.ac - Configure script for ndisc6
dnl based on earlier configure.ac from tcpreen by the same author

dnl Process this file with GNU Autoconf to produce a configure script

dnl ***********************************************************************
dnl *  Copyright © 2002-2006 Rémi Denis-Courmont.                         *
dnl *  This program is free software; you can redistribute and/or modify  *
dnl *  it under the terms of the GNU General Public License as published  *
dnl *  by the Free Software Foundation; version 2 of the license.         *
dnl *                                                                     *
dnl *  This program is distributed in the hope that it will be useful,    *
dnl *  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
dnl *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.               *
dnl *  See the GNU General Public License for more details.               *
dnl *                                                                     *
dnl *  You should have received a copy of the GNU General Public License  *
dnl *  along with this program; if not, you can get it from:              *
dnl *  http://www.gnu.org/copyleft/gpl.html                               *
dnl ***********************************************************************

AC_COPYRIGHT([Copyright (C) 2005-2006 Remi Denis-Courmont])
AC_INIT(ndisc6, 0.6.8, rdenis@simphalempin.com)
AC_PREREQ(2.59c)
INVOCATION="$0 $*"

AS_MESSAGE(checking system...)
AC_CONFIG_SRCDIR(configure.ac)
AC_CONFIG_AUX_DIR(admin)
AC_CONFIG_MACRO_DIR(m4)
AC_CONFIG_HEADERS(config.h)

AC_DEFINE_UNQUOTED(PACKAGE_CONFIGURE_INVOCATION, "$INVOCATION",
                   [Define to the command line used to invoke the configure script.])
RDC_BUILD_HOSTNAME


# Checks for programs.
AS_MESSAGE([checking required programs...])
AC_PROG_CC_C99
AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE([check-news dist-bzip2 no-dist-gzip no-exeext std-options])


# Checks for libraries.
AS_MESSAGE([checking required libraries...])
dnl AM_GNU_GETTEXT_VERSION([0.12.1])
dnl AM_GNU_GETTEXT([external])

dnl AC_DEFINE_UNQUOTED(PACKAGE_BUILD, "$build",
dnl                    [Define to the canonical build-system name])
dnl AC_DEFINE_UNQUOTED(PACKAGE_HOST, "$host",
dnl                    [Define to the canonical host-system name])

# Checks for header files.
dnl AS_MESSAGE([checking header files...])


# Checks for typedefs, structures, and compiler characteristics.
dnl AS_MESSAGE([checking target characteristics...])
dnl AC_C_BIGENDIAN
dnl RDC_STRUCT_SOCKADDR_LEN


# Checks for library functions.
AS_MESSAGE([checking library functions...])
RDC_REPLACE_FUNC_GETOPT_LONG
AC_SEARCH_LIBS(clock_gettime, [rt])
AC_CHECK_FUNC([clock_nanosleep])

# Network stuff
RDC_FUNC_SOCKET
AC_SEARCH_LIBS(inet_ntop, [nsl])

# Checks for optionnal features
AS_MESSAGE([checking optional features...])
AC_MSG_CHECKING([if installed programs should be setuid])
AC_ARG_ENABLE(suid-install,
              [AS_HELP_STRING(--disable-suid-install,
                              [do not set the SetUID bit on installed programs])])
AS_IF([test "x${enable_suid_install}" != "xno"],
	[enable_suid_install=yes])
AM_CONDITIONAL(NOSUID, [test "${enable_suid_install}" = "no"])
AC_MSG_RESULT([${enable_suid_install}])


# Defines for <config.h>
AH_BOTTOM([
#ifndef HAVE_CLOCK_NANOSLEEP
# define clock_nanosleep( c, f, d, r ) nanosleep( d, r )
#endif

#define _( str )		gettext (str)
#define N_( str )		gettext_noop (str)
#define gettext( str )		(str)
#define gettext_noop( str )	(str)
#define ngettext( a, b, c ) (((c) == 1) ? (a) : (b))
])


# END
AS_MESSAGE(writing results...)
AC_CONFIG_FILES([Makefile m4/Makefile src/Makefile])
AC_OUTPUT
