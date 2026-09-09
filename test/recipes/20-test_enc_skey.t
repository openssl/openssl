#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Compare qw/compare/;
use OpenSSL::Test qw/:DEFAULT bldtop_dir with/;
use OpenSSL::Test::Utils;

setup("test_enc_skey");

# The opaque key roundtrip through a provider-implemented cipher needs the
# loadable fake-cipher provider, which is only built with module support.
my $fake_cipher = !disabled('module');

plan tests => 2 + ($fake_cipher ? 1 : 0);

my $key = "000102030405060708090a0b0c0d0e0f";
my $iv = "00112233445566778899aabbccddeeff";
my $plain = "plain.txt";

open my $fh, ">", $plain or die "Cannot write $plain: $!";
print $fh "Opaque symmetric key test payload." x 4, "\n";
close $fh;

# Helper: run enc expecting a non-zero (failure) exit code, and check that
# stderr matches a regular expression.
sub enc_fails {
    my ($testtext, $re, @args) = @_;

    my $stderr_file = "enc_skey_err.txt";
    my $err = '';

    with({ exit_checker => sub { return shift != 0; } },
        sub {
            ok(run(app(['openssl', 'enc', @args], stderr => $stderr_file)),
               $testtext);
        });

    if (open(my $fh, '<', $stderr_file)) {
        $err = do { local $/; <$fh> };
        close($fh);
    }
    ok($err =~ $re, "$testtext: stderr matches");
    unlink($stderr_file) if -f $stderr_file;
}

subtest "enc with an opaque key matches raw key encryption" => sub {
    plan tests => 5;

    ok(run(app(['openssl', 'enc', '-aes-128-cbc', '-e',
                '-skeymgmt', 'AES', '-skeyopt', "hexraw-bytes:$key",
                '-iv', $iv, '-in', $plain, '-out', 'enc_skey.bin'])),
       "encrypt with an opaque key built from -skeyopt raw bytes");
    ok(run(app(['openssl', 'enc', '-aes-128-cbc', '-e',
                '-K', $key, '-iv', $iv,
                '-in', $plain, '-out', 'enc_raw.bin'])),
       "encrypt with the same raw key");
    is(compare('enc_skey.bin', 'enc_raw.bin'), 0,
       "opaque and raw key encryption produce the same ciphertext");
    ok(run(app(['openssl', 'enc', '-aes-128-cbc', '-d',
                '-skeymgmt', 'AES', '-skeyopt', "hexraw-bytes:$key",
                '-iv', $iv, '-in', 'enc_skey.bin', '-out', 'dec_skey.txt'])),
       "decrypt with the opaque key");
    is(compare('dec_skey.txt', $plain), 0,
       "decryption with the opaque key recovers the plaintext");
};

subtest "enc opaque key error handling" => sub {
    plan tests => 8;

    enc_fails("a raw key and -skeyopt together are rejected",
              qr/Either a raw key or the skeyopt\/skeyuri args must be used/,
              '-aes-128-cbc', '-e', '-K', $key, '-iv', $iv,
              '-skeyopt', "hexraw-bytes:$key", '-in', $plain);
    enc_fails("an unknown -skeymgmt is rejected",
              qr/Error creating opaque key object for skeymgmt NoSuchMgmt/,
              '-aes-128-cbc', '-e', '-skeymgmt', 'NoSuchMgmt',
              '-skeyopt', "hexraw-bytes:$key", '-iv', $iv, '-in', $plain);
    enc_fails("an unknown -skeyopt parameter is rejected",
              qr/Parameter unknown 'nosuchopt:1'/,
              '-aes-128-cbc', '-e', '-skeymgmt', 'AES',
              '-skeyopt', 'nosuchopt:1', '-iv', $iv, '-in', $plain);
    enc_fails("a malformed -skeyopt without a value is rejected",
              qr/Parameter error 'raw-bytes'/,
              '-aes-128-cbc', '-e', '-skeymgmt', 'AES',
              '-skeyopt', 'raw-bytes', '-iv', $iv, '-in', $plain);
};

# The fake-cipher provider names both its cipher and its skey management
# "fake_cipher", so it also covers defaulting the skeymgmt name to the
# cipher name when -skeymgmt is not given.
if ($fake_cipher) {
    subtest "enc with an opaque key from the fake-cipher provider" => sub {
        plan tests => 4;

        $ENV{OPENSSL_MODULES} = bldtop_dir("test");
        my @prov = ('-provider-path', bldtop_dir("test"),
                    '-provider', 'fake-cipher', '-provider', 'default');

        ok(run(app(['openssl', 'enc', @prov, '-fake_cipher', '-e',
                    '-skeyopt', 'key_name:testkey',
                    '-skeyopt', "hexraw-bytes:$key",
                    '-in', $plain, '-out', 'enc_fake.bin'])),
           "encrypt with an opaque key without -skeymgmt");
        isnt(compare('enc_fake.bin', $plain), 0,
             "the fake cipher transformed the plaintext");
        ok(run(app(['openssl', 'enc', @prov, '-fake_cipher', '-d',
                    '-skeyopt', "hexraw-bytes:$key",
                    '-in', 'enc_fake.bin', '-out', 'dec_fake.txt'])),
           "decrypt with the opaque key without -skeymgmt");
        is(compare('dec_fake.txt', $plain), 0,
           "decryption with the opaque key recovers the plaintext");
    };
}
