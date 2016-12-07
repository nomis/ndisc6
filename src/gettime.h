/*
 * gettime.h - compatibility wrapper around clock_gettime()
 */

/*************************************************************************
 *  Copyright © 2006 Rémi Denis-Courmont.                                *
 *  This program is free software: you can redistribute and/or modify    *
 *  it under the terms of the GNU General Public License as published by *
 *  the Free Software Foundation, versions 2 or 3 of the license.        *
 *                                                                       *
 *  This program is distributed in the hope that it will be useful,      *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of       *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        *
 *  GNU General Public License for more details.                         *
 *                                                                       *
 *  You should have received a copy of the GNU General Public License    *
 *  along with this program. If not, see <http://www.gnu.org/licenses/>. *
 *************************************************************************/

#include <unistd.h>
#include <errno.h>

static inline int mono_gettime (struct timespec *ts)
{
	int rc;

#if (_POSIX_MONOTONIC_CLOCK >= 0)
	rc = clock_gettime (CLOCK_MONOTONIC, ts);
#endif
#if (_POSIX_MONOTONIC_CLOCK == 0)
	if (errno == EINVAL)
#endif
#if (_POSIX_MONOTONIC_CLOCK <= 0)
		rc = clock_gettime (CLOCK_REALTIME, ts);
#endif
	return rc;
}


static inline int mono_nanosleep (const struct timespec *ts)
{
	int rc;

#if (_POSIX_MONOTONIC_CLOCK >= 0)
	rc = clock_nanosleep (CLOCK_MONOTONIC, 0, ts, NULL);
#endif
#if (_POSIX_MONOTONIC_CLOCK == 0)
	if (rc == EINVAL)
#endif
#if (_POSIX_MONOTONIC_CLOCK <= 0)
		rc = clock_nanosleep (CLOCK_REALTIME, 0, ts, NULL);
#endif
	return rc;
}
