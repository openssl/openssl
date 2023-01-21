#! /usr/bin/env perl
# Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test::Utils;
use File::Compare qw(compare_text);
use OpenSSL::Test qw/:DEFAULT srctop_file ok_nofips is_nofips/;

setup("test_pkcs8");

plan tests => 3;

SKIP: {
    skip "SM2, SM3 or SM4 is not supported by this OpenSSL build", 3
        if disabled("sm2") || disabled("sm3") || disabled("sm4");

    ok_nofips(run(app(([ 'openssl', 'pkcs8', '-topk8',
                      '-in', srctop_file('test', 'certs', 'sm2.key'),
                      '-out', 'sm2-pbes2-sm4-hmacWithSM3.key',
                      '-passout', 'pass:password',
                      '-v2', 'sm4', '-v2prf', 'hmacWithSM3']))),
                      "Convert a private key to PKCS#5 v2.0 format using SM4 and hmacWithSM3");

    ok_nofips(run(app(([ 'openssl', 'pkcs8', '-topk8',
                      '-in', 'sm2-pbes2-sm4-hmacWithSM3.key',
                      '-out', 'sm2.key',
                      '-passin', 'pass:password', '-nocrypt',
                      '-v2', 'sm4', '-v2prf', 'hmacWithSM3']))),
                      "Convert from PKCS#5 v2.0 format to PKCS#8 unencrypted format");

    is_nofips(compare_text(srctop_file('test', 'certs', 'sm2.key'), 'sm2.key',
        sub {
            my $in1 = $_[0];
            my $in2 = $_[1];
            $in1 =~ s/\r\n/\n/g;
            $in2 =~ s/\r\n/\n/g;
            $in1 ne $in2
        }), 0, "compare test/certs/sm2.key to sm2.key")
}
