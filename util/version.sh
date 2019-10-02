#! /bin/sh
# Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

HERE=`dirname $0`

versionheader="$1"
if [ -z "$versionheader" ]; then
    versionheader="$HERE/../include/openssl/opensslv.h"
fi

version1macros="OPENSSL_VERSION_TEXT|SHLIB_VERSION_NUMBER"
currentmacros="OPENSSL_VERSION_MAJOR|OPENSSL_VERSION_MINOR|OPENSSL_VERSION_PATCH|OPENSSL_VERSION_PRE_RELEASE|OPENSSL_VERSION_BUILD_METADATA|OPENSSL_SHLIB_VERSION"

eval $(
    grep -E "^# *define  *($version1macros|$currentmacros) " "$versionheader" | \
        while read L; do
            echo $L | sed -e 's|^# *define *||' -e 's|  *|=|'
        done
    )

if [ -n "$OPENSSL_VERSION_MAJOR" ]; then
    # OpenSSL 3.0 and on
    OPENSSL_VERSION_STR="$OPENSSL_VERSION_MAJOR.$OPENSSL_VERSION_MINOR.$OPENSSL_VERSION_PATCH"
    OPENSSL_FULL_VERSION_STR="$OPENSSL_VERSION_STR$OPENSSL_VERSION_PRE_RELEASE$OPENSSL_VERSION_BUILD_METADATA"
else
    # OpenSSL before 3.0
    OPENSSL_FULL_VERSION_STR=`echo "$OPENSSL_VERSION_TEXT" | cut -f2 -d' '`
    OPENSSL_VERSION_STR=`echo "$OPENSSL_FULL_VERSION_STR" | cut -f1 -d-`
    OPENSSL_SHLIB_VERSION="$SHLIB_VERSION_NUMBER"
fi

for x in `IFS='|'; echo $version1macros $currentmacros` \
             OPENSSL_VERSION_STR OPENSSL_FULL_VERSION_STR; do
    eval "echo $x=\"\\\"\$$x\\\"\""
done
