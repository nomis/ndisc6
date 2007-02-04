#define _GNU_SOURCE 1

#define gettext( str ) (str)
#define gettext_noop( str ) (str)
#define _( str ) gettext (str)
#define N_( str ) gettext_noop (str)

