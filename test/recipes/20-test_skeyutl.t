#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT with/;
use OpenSSL::Test::Utils;

setup("test_skeyutl");

plan tests => 14;

# Helper: run skeyutl expecting a non-zero (failure) exit code, and optionally
# check that stderr matches a regular expression.
sub skeyutl_fails {
    my ($testtext, $re, @args) = @_;

    my $stderr_file = "skeyutl_err.txt";
    my $err = '';

    with({ exit_checker => sub { return shift != 0; } },
        sub {
            ok(run(app(['openssl', 'skeyutl', @args], stderr => $stderr_file)),
               $testtext);
        });

    if (defined $re) {
        if (open(my $fh, '<', $stderr_file)) {
            $err = do { local $/; <$fh> };
            close($fh);
        }
        ok($err =~ $re, "$testtext: stderr matches");
    }
    unlink($stderr_file) if -f $stderr_file;
}

# -help exits successfully
ok(run(app(['openssl', 'skeyutl', '-help'])),
   "skeyutl -help succeeds");

# Neither -cipher nor -skeymgmt is given
skeyutl_fails("skeyutl without -cipher or -skeymgmt fails",
              qr/Either -skeymgmt -or -cipher option should be specified/);

# -genkey but neither -cipher nor -skeymgmt is given: same early check
skeyutl_fails("skeyutl -genkey without -cipher or -skeymgmt fails",
              qr/Either -skeymgmt -or -cipher option should be specified/,
              '-genkey');

# A cipher is given but -genkey is not: generation is the only operation
skeyutl_fails("skeyutl without -genkey reports unsupported operation",
              qr/Key generation is the only supported operation/,
              '-cipher', 'AES-128-CBC');

# -genkey with a valid skey management name: reaches the generation path
# (no built-in provider supports opaque key generation yet)
skeyutl_fails("skeyutl -genkey with valid -skeymgmt reaches generation",
              qr/Error creating opaque key for skeymgmt AES/,
              '-genkey', '-skeymgmt', 'AES');

# -genkey with an unknown skey management name: fetch fails
skeyutl_fails("skeyutl -genkey with unknown -skeymgmt fails",
              undef,
              '-genkey', '-skeymgmt', 'NoSuchSkeyMgmt');

# An unknown cipher name is rejected by option parsing
skeyutl_fails("skeyutl with an unknown cipher fails",
              qr/Unknown option or cipher/,
              '-genkey', '-cipher', 'NoSuchCipher');

# An unknown option is rejected
skeyutl_fails("skeyutl with an unknown option fails",
              qr/Unknown option/,
              '-not-an-option');
