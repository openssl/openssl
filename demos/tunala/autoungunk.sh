#!/bin/sh

# This script tries to clean up as much as is possible from whatever diabolical
# mess has been left in the directory thanks to autoconf, automake, and their
# friends.

if test -f Makefile; then
	make distclean
	rm -f Makefile
fi

if test -f Makefile.plain; then
	mv Makefile.plain Makefile
fi

rm -f aclocal.m4 config.* configure install-sh \
	missing mkinstalldirs stamp-h.* Makefile.in \
	ltconfig ltmain.sh
