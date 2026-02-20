#!/bin/sh -ex
#
# Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# krb5's test suite clears LD_LIBRARY_PATH
LDFLAGS="-L`pwd`/$BLDTOP -Wl,-rpath,`pwd`/$BLDTOP"
CFLAGS="-I`pwd`/$BLDTOP/include -I`pwd`/$SRCTOP/include"

unpatch() {
    cd "$SRC_ABS_TOP/krb5" && git reset --hard "$GITLEVEL"
}

trap unpatch EXIT

cd $SRCTOP
SRC_ABS_TOP=$PWD;
DATA_ABS_TOP=$SRC_ABS_TOP/test/recipes/95-test_external_krb5_data

cd $SRC_ABS_TOP/krb5
GITLEVEL=$(git rev-parse HEAD)
# "git am" refuses to run without a user configured.
# However, our CLA check then appears to pick up this git
# username  to decide if it is going to complain, so I need
# to set this to a user the CLA knows about instead
# of a made up email address of "dirtbag@openssl.org".
#
# I leave it as an exercise to the reader for how to get
# around the CLA check on arbitrary commits..
git config user.email "beck@obtuse.com"
git config user.name "I do dirty things with Git"
for FILE in "$DATA_ABS_TOP"/patches/*; do
    if [ -f "$FILE" ]; then
	git am $FILE
    fi
done
cd $SRC_ABS_TOP/krb5/src

autoreconf
./configure --with-ldap --with-prng-alg=os --enable-pkinit \
            --with-crypto-impl=openssl --with-tls-impl=openssl \
            CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS"

# quiet make so that Travis doesn't overflow
make -s

make check
