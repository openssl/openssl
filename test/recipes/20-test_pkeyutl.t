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
use OpenSSL::Test qw/:DEFAULT srctop_file ok_nofips/;
use OpenSSL::Test::Utils;

setup("test_pkeyutl");

plan tests => 6;

# For the tests below we use the cert itself as the TBS file

SKIP: {
    skip "Skipping tests that require EC, SM2 or SM3", 2
        if disabled("ec") || disabled("sm2") || disabled("sm3");

    # SM2
    ok_nofips(run(app(([ 'openssl', 'pkeyutl', '-sign',
                      '-in', srctop_file('test', 'certs', 'sm2.pem'),
                      '-inkey', srctop_file('test', 'certs', 'sm2.key'),
                      '-out', 'signature.dat', '-rawin',
                      '-digest', 'sm3', '-pkeyopt', 'sm2_id:someid']))),
                      "Sign a piece of data using SM2");
    ok_nofips(run(app(([ 'openssl', 'pkeyutl', '-verify', '-certin',
                      '-in', srctop_file('test', 'certs', 'sm2.pem'),
                      '-inkey', srctop_file('test', 'certs', 'sm2.pem'),
                      '-sigfile', 'signature.dat', '-rawin',
                      '-digest', 'sm3', '-pkeyopt', 'sm2_id:someid']))),
                      "Verify an SM2 signature against a piece of data");
}

SKIP: {
    skip "Skipping tests that require EC", 4
        if disabled("ec");

    # Ed25519
    ok(run(app(([ 'openssl', 'pkeyutl', '-sign', '-in',
                  srctop_file('test', 'certs', 'server-ed25519-cert.pem'),
                  '-inkey', srctop_file('test', 'certs', 'server-ed25519-key.pem'),
                  '-out', 'signature.dat', '-rawin']))),
                  "Sign a piece of data using Ed25519");
    ok(run(app(([ 'openssl', 'pkeyutl', '-verify', '-certin', '-in',
                  srctop_file('test', 'certs', 'server-ed25519-cert.pem'),
                  '-inkey', srctop_file('test', 'certs', 'server-ed25519-cert.pem'),
                  '-sigfile', 'signature.dat', '-rawin']))),
                  "Verify an Ed25519 signature against a piece of data");

    # Ed448
    ok(run(app(([ 'openssl', 'pkeyutl', '-sign', '-in',
                  srctop_file('test', 'certs', 'server-ed448-cert.pem'),
                  '-inkey', srctop_file('test', 'certs', 'server-ed448-key.pem'),
                  '-out', 'signature.dat', '-rawin']))),
                  "Sign a piece of data using Ed448");
    ok(run(app(([ 'openssl', 'pkeyutl', '-verify', '-certin', '-in',
                  srctop_file('test', 'certs', 'server-ed448-cert.pem'),
                  '-inkey', srctop_file('test', 'certs', 'server-ed448-cert.pem'),
                  '-sigfile', 'signature.dat', '-rawin']))),
                  "Verify an Ed448 signature against a piece of data");
}

unlink 'signature.dat';
