#!/bin/sh

# requires SRCTOP to be set to the top of the source directory.
: "${SRCTOP:?SRCTOP must be set to the top of the source tree}"

check_headers() {
  for header in "$@"
  do
      cd "${SRCTOP}/${header/*}"
      cc -I ${SRCTOP}/include -I . -c $1
      shift;
  done
}

check_headers $(find $SRCTOP/include -name '*.h')
#check_headers $(find $SRCTOP/crypto -name '*.h')
check_headers $(find $SRCTOP/ssl -name '*.h')
#check_headers $(find $SRCTOP/apps -name '*.h')
#check_headers $(find $SRCTOP/providers -name '*.h')
