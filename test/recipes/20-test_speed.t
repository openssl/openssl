#! /usr/bin/env perl
# Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use File::Basename;
use OpenSSL::Test qw/:DEFAULT with srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;

setup("test_speed");

# -bytes sizes symmetric inputs, not public-key signatures or ciphertext.
my @buffer_tests = (
    [ "RSA", [], "rsa2048" ],
    [ "ECDSA", [qw(ec)], "ecdsap521" ],
);

plan tests => 25 + scalar @buffer_tests;

foreach my $test (@buffer_tests) {
    my ($name, $disabled, $algorithm) = @$test;

    subtest "$name works with small -bytes" => sub {
        plan skip_all => "$name is not supported by this OpenSSL build"
            if disabled(@$disabled);

        local $ENV{OPENSSL_CONF} = srctop_file("test", "default.cnf");
        local $ENV{OPENSSL_MODULES} = bldtop_dir("providers");
        foreach my $bytes (1, 16) {
            foreach my $misalign (0, 63) {
                my @alignment = $misalign ? ('-misalign', $misalign) : ();

                ok(run(app(['openssl', 'speed', '-testmode', '-bytes', $bytes,
                            @alignment, $algorithm])),
                   "$name succeeds with $bytes-byte inputs at offset $misalign");
            }
        }
        done_testing();
    };
}

ok(run(app(['openssl', 'speed', '-testmode'])),
       "Simple test of all speed algorithms");

#Test various options to speed. In all cases we use the -testmode option to
#ensure we don't spend too long in this test. That option also causes the speed
#app to return an error code if anything unexpectedly goes wrong.


SKIP: {
    skip "Multi option is not supported by this OpenSSL build", 1
       if $^O =~ /^(VMS|MSWin32)$/;

    ok(run(app(['openssl', 'speed', '-testmode', '-multi', 2])),
           "Test the multi option");
}

ok(run(app(['openssl', 'speed', '-testmode', '-misalign', 1])),
       "Test the misalign option");

SKIP: {
    skip "Multiblock is not supported by this OpenSSL build", 1
        if disabled("multiblock")
           # The AES-128-CBC-HMAC-SHA1 cipher isn't available on all platforms
           # We test its availability without the "-mb" option. We only do the
           # multiblock test via "-mb" if the cipher seems to exist.
           || !run(app(['openssl', 'speed', '-testmode', '-evp',
                       'AES-128-CBC-HMAC-SHA1']));

    ok(run(app(['openssl', 'speed', '-testmode', '-mb', '-evp',
                'AES-128-CBC-HMAC-SHA1'])),
        "Test the EVP and mb options");
}

ok(run(app(['openssl', 'speed', '-testmode', '-kem-algorithms'])),
       "Test the kem-algorithms option");

ok(run(app(['openssl', 'speed', '-testmode', '-signature-algorithms'])),
       "Test the signature-algorithms option");

ok(run(app(['openssl', 'speed', '-testmode', '-primes', 3, 'rsa1024'])),
       "Test the primes option");

ok(run(app(['openssl', 'speed', '-testmode', '-mr'])),
       "Test the mr option");

ok(run(app(['openssl', 'speed', '-testmode', '-decrypt', '-evp', 'aes-128-cbc'])),
       "Test the decrypt and evp options");

ok(run(app(['openssl', 'speed', '-testmode', '-evp', 'sha256'])),
       "Test the evp option with a digest");

ok(run(app(['openssl', 'speed', '-testmode', '-hmac', 'sha256'])),
       "Test the hmac option");

SKIP: {
    skip "CMAC is not supported by this OpenSSL build", 1
        if disabled("cmac");

    ok(run(app(['openssl', 'speed', '-testmode', '-cmac', 'aes-128-cbc'])),
           "Test the cmac option");
}

ok(run(app(['openssl', 'speed', '-testmode', '-aead', '-evp', 'aes-128-gcm'])),
       "Test the aead and evp options");

SKIP: {
    skip "ASYNC/threads not supported by this OpenSSL build", 1
        if disabled("async") || disabled("threads");

    ok(run(app(['openssl', 'speed', '-testmode', '-async_jobs', '1'])),
        "Test the async_jobs option");
}

SKIP: {
    skip "Mlock option is not supported by this OpenSSL build", 1
       if $^O !~ /^(linux|MSWin32)$/;

       ok(run(app(['openssl', 'speed', '-testmode', '-mlock'])),
              "Test the mlock option");
}

#We don't expect these options to have an effect in testmode but we at least
#test that the option parsing works ok
ok(run(app(['openssl', 'speed', '-testmode', '-seconds', 1, '-bytes', 16,
            '-elapsed'])),
       "Test the seconds, bytes and elapsed options");

#Test that this won't crash on sparc
ok(run(app(['openssl', 'speed', '-testmode', '-seconds', 1, '-bytes', 1,
            'aes-128-cbc'])),
       "Test that bad bytes value doesn't make speed to crash");

#No need to -testmode for testing -help. All we're doing is testing the option
#parsing. We don't sanity check the output
ok(run(app(['openssl', 'speed', '-help'])),
       "Test the help option");

#Now test some invalid options. The speed app should fail
ok(!run(app(['openssl', 'speed', 'blah'])),
        "Test an unknown algorithm");

ok(!run(app(['openssl', 'speed', '-evp', 'blah'])),
        "Test a unknown evp algorithm");

ok(!run(app(['openssl', 'speed', '-hmac', 'blah'])),
        "Test a unknown hmac algorithm");

ok(!run(app(['openssl', 'speed', '-cmac', 'blah'])),
        "Test a unknown cmac algorithm");

ok(!run(app(['openssl', 'speed', '-async_jobs', 100000])),
        "Test an invalid number of async_jobs");

ok(!run(app(['openssl', 'speed', '-misalign', 65])),
        "Test an invalid misalign number");

SKIP: {
    skip "Multiblock is not supported by this OpenSSL build", 1
        if disabled("multiblock");

    ok(!run(app(['openssl', 'speed', '-testmode', '-mb', '-evp',
                'AES-128-CBC'])),
            "Test a non multiblock cipher with -mb");
}
