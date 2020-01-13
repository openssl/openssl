#!/bin/sh

HERE="`echo $0 | sed -e 's|[^/]*$||'`"
OPENtls="${HERE}../apps/opentls"

if [ -d "${HERE}../engines" -a "x$OPENtls_ENGINES" = "x" ]; then
	OPENtls_ENGINES="${HERE}../engines"; export OPENtls_ENGINES
fi
if [ -d "${HERE}../providers" -a "x$OPENtls_MODULES" = "x" ]; then
	OPENtls_MODULES="${HERE}../providers"; export OPENtls_MODULES
fi

if [ -x "${OPENtls}.exe" ]; then
	# The original reason for this script existence is to work around
	# certain caveats in run-time linker behaviour. On Windows platforms
	# adjusting $PATH used to be sufficient, but with introduction of
	# SafeDllSearchMode in XP/2003 the only way to get it right in
	# *all* possible situations is to copy newly built .DLLs to apps/
	# and test/, which is now done elsewhere... The $PATH is adjusted
	# for backward compatibility (and nostagical reasons:-).
	if [ "$OSTYPE" != msdosdjgpp ]; then
		PATH="${HERE}..:$PATH"; export PATH
	fi
	exec "${OPENtls}.exe" "$@"
elif [ -x "${OPENtls}" -a -x "${HERE}shlib_wrap.sh" ]; then
	exec "${HERE}shlib_wrap.sh" "${OPENtls}" "$@"
else
	exec "${OPENtls}" "$@"	# hope for the best...
fi
