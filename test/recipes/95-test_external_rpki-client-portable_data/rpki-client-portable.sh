#!/bin/sh -ex
#
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# krb5's test suite clears LD_LIBRARY_PATH
LDFLAGS="-L`pwd`/$BLDTOP -Wl,-rpath,`pwd`/$BLDTOP"
CFLAGS="-I`pwd`/$BLDTOP/include -I`pwd`/$SRCTOP/include"

cd $SRCTOP/rpki-client-portable

./autogen.sh

./configure --with-openssl-cflags="$CFLAGS" --with-openssl-ldflags="$LDFLAGS" \
            CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS"

# quiet make so that Travis doesn't overflow
make

make check
