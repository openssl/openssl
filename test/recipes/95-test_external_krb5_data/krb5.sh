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
for FILE in "$DATA_ABS_TOP"/patches/*; do
    if [ -f "$FILE" ]; then
	git -c 'user.name=OpenSSL External Tests' -c 'user.email=nonsuch@openssl.org' am $FILE
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
