#!/bin/sh

rm -f "$2"
if test "$OSTYPE" = msdosdjgpp || test "x$PLATFORM" = xmingw || test "x$OS" = xWindows_NT ; then
    cp "$1" "$2"
else
    ln -s "$1" "$2"
fi
echo "$2 => $1"

