#! /usr/bin/env perl
# Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT with/;
use OpenSSL::Test::Utils;

setup("test_genpkey");

my @algs = ();
push @algs, qw(RSA) unless disabled("rsa");
push @algs, qw(DSA) unless disabled("dsa");
push @algs, qw(DH DHX) unless disabled("dh");
push @algs, qw(EC) unless disabled("ec");
push @algs, qw(X25519 X448) unless disabled("ecx");
push @algs, qw(SM2) unless disabled("sm2");

plan tests => scalar(@algs) + 2;

foreach (@algs) {
    my $alg = $_;

    ok(run(app([ 'openssl', 'genpkey', '-algorithm', $alg, '-help'])),
       "show genpkey pkeyopt values for $alg");
}

SKIP: {
    skip "RSA is not supported by this OpenSSL build", 1 if disabled("rsa");

    subtest "genpkey with a cipher encrypts the private key" => sub {
        plan tests => 3;

        my $key = "genpkey_enc.pem";

        ok(run(app(['openssl', 'genpkey', '-algorithm', 'RSA',
                    '-pkeyopt', 'rsa_keygen_bits:512',
                    '-aes256', '-pass', 'pass:secret', '-out', $key])),
           "Generate an AES-256 encrypted RSA key");
        ok(run(app(['openssl', 'pkey', '-in', $key,
                    '-passin', 'pass:secret', '-noout'])),
           "Read the encrypted key back with the correct passphrase");
        # A wrong passphrase must not decrypt the key.
        with({ exit_checker => sub { return shift == 1; } },
            sub {
                ok(run(app(['openssl', 'pkey', '-in', $key,
                            '-passin', 'pass:wrong', '-noout'])),
                   "Reading with a wrong passphrase fails");
            });
    };
}

SKIP: {
    skip "DSA is not supported by this OpenSSL build", 1 if disabled("dsa");

    # A cipher only encrypts a private key, so it is rejected with -genparam.
    with({ exit_checker => sub { return shift == 1; } },
        sub {
            ok(run(app(['openssl', 'genpkey', '-genparam', '-algorithm', 'DSA',
                        '-pkeyopt', 'dsa_paramgen_bits:512', '-aes256'])),
               "Cannot use a cipher with -genparam");
        });
}
