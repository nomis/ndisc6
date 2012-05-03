#!/bin/sh
# VCS package rebuild script

# *************************************************************************
# *  Copyright © 2006 Rémi Denis-Courmont.                                *
# *  This program is free software: you can redistribute and/or modify    *
# *  it under the terms of the GNU General Public License as published by *
# *  the Free Software Foundation, version 2 or 3.                        *
# *                                                                       *
# *  This program is distributed in the hope that it will be useful,      *
# *  but WITHOUT ANY WARRANTY; without even the implied warranty of       *
# *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        *
# *  GNU General Public License for more details.                         *
# *                                                                       *
# *  You should have received a copy of the GNU General Public License    *
# *  along with this program. If not, see <http://www.gnu.org/licenses/>. *
# *************************************************************************

cd "$(dirname "$0")" || exit 1

echo "Creating admin directory ..."
test -d admin || mkdir admin || exit 1

echo "Running autoreconf ..."
autoreconf -sfi
unlink po/Makevars.template

for d in /usr /usr/local /opt/gettext /usr/pkg $HOME ; do
	if test -f $d/share/gettext/gettext.h ; then
		ln -sf $d/share/gettext/gettext.h include/gettext.h
	fi
done

test -f "include/gettext.h" || {
echo "Error: can't find <gettext.h> convenience C header."
echo "Please put a link to it by hand as include/gettext.h"
}

echo ""
echo "Type \`./configure' to configure the package for your system"
echo "(type \`./configure -- help' for help)."
echo "Then you can use the usual \`make', \`make install', etc."

