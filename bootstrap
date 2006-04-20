#!/bin/sh
# SVN package rebuild script
# $Id$
#
# ***********************************************************************
# *  Copyright © 2002-2006 Rémi Denis-Courmont.                         *
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

if test ! -f doc/rdisc6.8 ; then
	echo "You must run this script from your miredo SVN directory."
	exit 1
fi

echo "Creating admin directory ..."
test -d admin || mkdir admin || exit 1

echo "Generating \`aclocal.m4' with aclocal ..."
aclocal -I m4 || {
echo "Error: autoconf is probably not on your system, or it does not work."
echo "You need GNU autoconf 2.54 or higher, as well as GNU gettext 0.12.1."
exit 1
}
echo "Generating \`config.h.in' with autoheader ..."
autoheader || exit 1
echo "Generating \`Makefile.in' with automake ..."
automake -Wall --add-missing || {
echo "Error: automake is probably not on your system, or it is too old."
echo "You need GNU automake 1.7 higher to rebuild this package."
exit 1
}
echo "Generating \`configure' script with autoconf ..."
autoconf || exit 1
echo "Done."

echo ""
echo "Type \`./configure' to configure the package for your system"
echo "(type \`./configure -- help' for help)."
echo "Then you can use the usual \`make', \`make install', etc."

