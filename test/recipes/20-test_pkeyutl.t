#! /usr/bin/env perl
# Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_pkeyutl");

plan skip_all => "test_pkeyutl needs EC, SM2 and SM3 enabled"
    if disabled("ec") || disabled("sm2") || disabled("sm3");


plan tests => 2;

sub sign
{
    # Utilize the sm2.crt as the TBS file
    return run(app(([ 'openssl', 'pkeyutl', '-sign',
                      '-in', srctop_file('test', 'certs', 'sm2.crt'),
                      '-inkey', srctop_file('test', 'certs', 'sm2.key'),
                      '-out', 'signature.sm2', '-rawin',
                      '-digest', 'sm3', '-pkeyopt', 'sm2_id:someid'])));
}

sub verify
{
    # Utilize the sm2.crt as the TBS file
    return run(app(([ 'openssl', 'pkeyutl', '-verify', '-certin',
                      '-in', srctop_file('test', 'certs', 'sm2.crt'),
                      '-inkey', srctop_file('test', 'certs', 'sm2.crt'),
                      '-sigfile', 'signature.sm2', '-rawin',
                      '-digest', 'sm3', '-pkeyopt', 'sm2_id:someid'])));
}

ok(sign, "Sign a piece of data using SM2");
ok(verify, "Verify an SM2 signature against a piece of data");

unlink 'signature.sm2';
