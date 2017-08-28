# ARG_ENABL_SET(option, help)
# ---------------------------
# Create a --enable-$1 option with helptext, set a variable $1 to true/false
# All $1 are collected in the variable $disabled_by_default
AC_DEFUN([ARG_ENABL_SET],
	[AC_ARG_ENABLE(
		[$1],
		AS_HELP_STRING([--enable-$1], [$2]),
		[patsubst([$1], [-], [_])_given=true
		if test x$enableval = xyes; then
			patsubst([$1], [-], [_])=true
		 else
			patsubst([$1], [-], [_])=false
		fi],
		[patsubst([$1], [-], [_])=false
		patsubst([$1], [-], [_])_given=false]
	)
	disabled_by_default=${disabled_by_default}" patsubst([$1], [-], [_])"]
)

# ARG_DISBL_SET(option, help)
# ---------------------------
# Create a --disable-$1 option with helptext, set a variable $1 to true/false
# All $1 are collected in the variable $enabled_by_default
AC_DEFUN([ARG_DISBL_SET],
	[AC_ARG_ENABLE(
		[$1],
		AS_HELP_STRING([--disable-$1], [$2]),
		[patsubst([$1], [-], [_])_given=true
		if test x$enableval = xyes; then
			patsubst([$1], [-], [_])=true
		 else
			patsubst([$1], [-], [_])=false
		fi],
		[patsubst([$1], [-], [_])=true
		patsubst([$1], [-], [_])_given=false]
	)
	enabled_by_default=${enabled_by_default}" patsubst([$1], [-], [_])"]
)
