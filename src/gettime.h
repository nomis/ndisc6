/*
 * gettime.h - compatibility wrapper around clock_gettime()
 * $Id$
 */

/***********************************************************************
 *  Copyright (C) 2006 Rémi Denis-Courmont.                            *
 *  This program is free software; you can redistribute and/or modify  *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; version 2 of the license.         *
 *                                                                     *
 *  This program is distributed in the hope that it will be useful,    *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.               *
 *  See the GNU General Public License for more details.               *
 *                                                                     *
 *  You should have received a copy of the GNU General Public License  *
 *  along with this program; if not, you can get it from:              *
 *  http://www.gnu.org/copyleft/gpl.html                               *
 ***********************************************************************/

#include <sys/times.h> /* times() fallback */

#if defined (CLOCK_HIGHRES) && !defined (CLOCK_MONOTONIC)
# define CLOCK_MONOTONIC CLOCK_HIGHRES
#endif

static inline void gettime (struct timespec *ts)
{
#ifdef CLOCK_MONOTONIC
	if (clock_gettime (CLOCK_MONOTONIC, ts))
#endif
	{
		struct tms dummy;
		clock_t t = times (&dummy);
		ts->tv_sec = t / 1000;
		ts->tv_nsec = (t % 1000) * 1000000;
	}
}

