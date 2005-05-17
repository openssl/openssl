#!/bin/sh

[ $# -ne 0 ] || set -x		# debug mode without arguments:-)

THERE="`echo $0 | sed -e 's|[^/]*$||' 2>/dev/null`.."
[ -d "${THERE}" ] || exec "$@"	# should never happen...

# Alternative to this is to parse ${THERE}/Makefile...
LIBCRYPTOSO="${THERE}/libcrypto.so"
if [ -f "$LIBCRYPTOSO" ]; then
    while [ -h "$LIBCRYPTOSO" ]; do
	LIBCRYPTOSO="${THERE}/`ls -l "$LIBCRYPTOSO" | sed -e 's|.*\-> ||'`"
    done
    SOSUFFIX=`echo ${LIBCRYPTOSO} | sed -e 's|.*\.so||' 2>/dev/null`
    LIBSSLSO="${THERE}/libssl.so${SOSUFFIX}"
fi

SYSNAME=`(uname -s) 2>/dev/null`;
case "$SYSNAME" in
SunOS|IRIX*)
	# SunOS and IRIX run-time linkers evaluate alternative
	# variables depending on target ABI...
	rld_var=LD_LIBRARY_PATH
	case "`(/usr/bin/file "$LIBCRYPTOSO") 2>/dev/null`" in
	*ELF\ 64*SPARC*)
		[ -n "$LD_LIBRARY_PATH_64" ] && rld_var=LD_LIBRARY_PATH_64
		;;
	*ELF\ N32*MIPS*)
		[ -n "$LD_LIBRARYN32_PATH" ] && rld_var=LD_LIBRARYN32_PATH
		_RLDN32_LIST="$LIBCRYPTOSO:$LIBSSLSO:DEFAULT"; export _RLDN32_LIST
		;;
	*ELF\ 64*MIPS*)
		[ -n "$LD_LIBRARY64_PATH"  ] && rld_var=LD_LIBRARY64_PATH
		_RLD64_LIST="$LIBCRYPTOSO:$LIBSSLSO:DEFAULT"; export _RLD64_LIST
		;;
	esac
	eval $rld_var=\"${THERE}:'$'$rld_var\"; export $rld_var
	unset rld_var
	;;
*)	LD_LIBRARY_PATH="${THERE}:$LD_LIBRARY_PATH"	# Linux, ELF HP-UX
	DYLD_LIBRARY_PATH="${THERE}:$DYLD_LIBRARY_PATH"	# MacOS X
	SHLIB_PATH="${THERE}:$SHLIB_PATH"		# legacy HP-UX
	LIBPATH="${THERE}:$LIBPATH"			# AIX, OS/2
	export LD_LIBRARY_PATH DYLD_LIBRARY_PATH SHLIB_PATH LIBPATH
	# Even though $PATH is adjusted [for Windows sake], it doesn't
	# necessarily does the trick. Trouble is that with introduction
	# of SafeDllSearchMode in XP/2003 it's more appropriate to copy
	# .DLLs in vicinity of executable, which is done elsewhere...
	if [ "$OSTYPE" != msdosdjgpp ]; then
		PATH="${THERE}:$PATH"; export PATH
	fi
	;;
esac

if [ -f "$LIBCRYPTOSO" ]; then
	# Following three lines are major excuse for isolating them into
	# this wrapper script. Original reason for setting LD_PRELOAD
	# was to make it possible to pass 'make test' when user linked
	# with -rpath pointing to previous version installation. Wrapping
	# it into a script makes it possible to do so on multi-ABI
	# platforms.
	case "$SYSNAME" in
	*BSD)	LD_PRELOAD="$LIBCRYPTOSO:$LIBSSLSO" ;;	# *BSD
	*)	LD_PRELOAD="$LIBCRYPTOSO $LIBSSLSO" ;;	# SunOS, Linux, ELF HP-UX
	esac
	_RLD_LIST="$LIBCRYPTOSO:$LIBSSLSO:DEFAULT"	# Tru64, o32 IRIX
	export LD_PRELOAD _RLD_LIST
fi

exec "$@"
