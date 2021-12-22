#!/bin/sh

# Copyright (c) 2014 Ian Sutton <ian@kremlin.cc>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# cd to root of repository
REPO=$(dirname "$(readlink -f $0)")/../
cd $REPO

if [[ $# -ne 1 ]];then
	echo "syntax: ./gen-dbus-interfaces <interface name>"
	exit 1
elif [[ $1 != "hostnamed" && $1 != "localed" && $1 != "timedated" && $1 != "logind" ]];then
	echo "<interface name> must be 'hostnamed', 'localed', 'timedated', or 'logind'"
	exit 1
fi

# cd to interface-specific source directory to avoid preprocessor pathing bug
cd src/interfaces/$1

gdbus-codegen \
--interface-prefix org.freedesktop. \
--generate-docbook $REPO/doc/$1-docbook.xml \
--generate-c-code  $1-gen \
$REPO/conf/introspect-xml/$1-ispect.xml

echo "Success"
exit 0
