#define VERSION "@VERSION@"
#define PACKAGE "@PACKAGE@"
#define PACKAGE_CONFIGURE_INVOCATION "cmake"
#define PACKAGE_BUILD_HOSTNAME "@SITE@"

#define _GNU_SOURCE 1

#cmakedefine HAVE_GETOPT_H 1

#cmakedefine HAVE_CLOCK_NANOSLEEP 1
#ifndef HAVE_CLOCK_NANOSLEEP
# define clock_nanosleep( c, f, d, r ) nanosleep( d, r )
#endif

#cmakedefine HAVE_INET6_RTH_ADD 1

#cmakedefine ENABLE_NLS 1
#define _( str ) gettext( str )
#define N_( str ) gettext_noop( str )
#define LOCALEDIR "@CMAKE_INSTALL_PREFIX@/share/locale"
