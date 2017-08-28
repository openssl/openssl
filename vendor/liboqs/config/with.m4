# ARG_WITH_SUBST(option, default, help)
# -----------------------------------
# Create a --with-$1 option with helptext, AC_SUBST($1) to $withval/default
AC_DEFUN([ARG_WITH_SUBST],
	[AC_ARG_WITH(
		[$1],
		AS_HELP_STRING([--with-$1=arg], [$3 (default: $2).]),
		[AC_SUBST(patsubst([$1], [-], [_]), ["$withval"])],
		[AC_SUBST(patsubst([$1], [-], [_]), ["$2"])]
	)]
)

# ARG_WITH_SET(option, default, help)
# -----------------------------------
# Create a --with-$1 option with helptext, set a variable $1 to $withval/default
AC_DEFUN([ARG_WITH_SET],
	[AC_ARG_WITH(
		[$1],
		AS_HELP_STRING([--with-$1=arg], [$3 (default: $2).]),
		patsubst([$1], [-], [_])="$withval",
		patsubst([$1], [-], [_])=$2
	)]
)

