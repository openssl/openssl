#! /bin/sh

HERE=`dirname $0`

VERSION=`grep 'OPENSSL_VERSION_TEXT  *"OpenSSL' $HERE/../include/openssl/opensslv.h | sed -e 's|.*"OpenSSL ||' -e 's| .*||'`
BASENAME=openssl

NAME="$BASENAME-$VERSION"

while [ $# -gt 0 ]; do
    case "$1" in
        --name=* ) NAME=`echo "$1" | sed -e 's|[^=]*=||'`   ;;
        --name ) shift; NAME="$1"                           ;;
        --tarfile=* ) TARFILE=`echo "$1" | sed -e 's|[^=]*=||'` ;;
        --tarfile ) shift; TARFILE="$1"                         ;;
    esac
    shift
done

if [ -z "$TARFILE" ]; then TARFILE="$NAME.tar"; fi

# This counts on .gitattributes to specify what files should be ignored
git archive --worktree-attributes --format=tar --prefix="$NAME/" -v HEAD \
    | gzip -9 > "$TARFILE.gz"

ls -l "$TARFILE.gz"
