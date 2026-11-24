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

# The second selection must run even though the first completed only once.
my @selection_tests = (
    [ "RSA", [], [qw(rsa512 rsa2048)],
      (map { [$_, [512, 2048]] } 1 .. 4),
      (map { [$_, [qw(rsa512 rsa2048)]] } 15 .. 20) ],
    [ "DSA", [qw(dsa)], [qw(dsa1024 dsa2048)],
      (map { [$_, [1024, 2048]] } 5 .. 6) ],
    [ "ECDSA", [qw(ec)], [qw(ecdsap256 ecdsap384)],
      (map { [$_, [qw(prime256v1 secp384r1)]] } 7 .. 8) ],
    [ "ECDH", [qw(ec)], [qw(ecdhp256 ecdhp384)],
      [9, [qw(prime256v1 secp384r1)]] ],
    [ "EdDSA", [qw(ecx)], [qw(ed25519 ed448)],
      (map { [$_, [qw(Ed25519 Ed448)]] } 7 .. 8) ],
    [ "ECX derive", [qw(ecx)], [qw(ecdhx25519 ecdhx448)],
      [9, [qw(X25519 X448)]] ],
    [ "SM2 sign", [qw(sm2)], [qw(ecdsap256 sm2)],
      (map { [$_, [qw(prime256v1 SM2)]] } 7 .. 8) ],
    [ "SM2 derive", [qw(sm2)], [qw(ecdhp256 curveSM2)],
      [9, [qw(prime256v1 SM2)]] ],
    [ "FFDH", [qw(dh)], [qw(ffdh2048 ffdh3072)],
      [14, [2048, 3072]] ],
    [ "KEM", [qw(ml-kem)], [qw(ML-KEM-512 ML-KEM-768)],
      (map { [$_, [qw(ML-KEM-512 ML-KEM-768)]] } 15 .. 17) ],
    [ "generic signatures", [qw(ml-dsa)], [qw(ML-DSA-44 ML-DSA-65)],
      (map { [$_, [qw(ML-DSA-44 ML-DSA-65)]] } 18 .. 20) ],
);

plan tests => 26 + scalar @buffer_tests + scalar @selection_tests;

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

foreach my $test (@selection_tests) {
    my ($name, $disabled, $algorithms, @operations) = @$test;

    subtest "testmode completes earlier and later $name selections" => sub {
        plan skip_all => "$name is not supported by this OpenSSL build"
            if disabled(@$disabled);

        # Keep machine-wide provider configuration out of these selection tests.
        local $ENV{OPENSSL_CONF} = srctop_file("test", "default.cnf");
        local $ENV{OPENSSL_MODULES} = bldtop_dir("providers");
        my $stderr = "speed-selection.err";

        ok(run(app(['openssl', 'speed', '-testmode', '-mr', @$algorithms],
                   stderr => $stderr)),
           "selected algorithms succeed");
        open my $fh, '<', $stderr or die "Cannot open $stderr: $!";
        my $output = do { local $/; <$fh> };
        close $fh;
        unlink $stderr;

        # Check completed operations, not just announcements of work to be done.
        foreach my $operation (@operations) {
            my ($tag, $entries) = @$operation;

            foreach my $entry (@$entries) {
                like($output, qr/^\+R$tag:1:\Q$entry\E:/m,
                     "$entry completes operation R$tag exactly once");
            }
        }
        done_testing();
    };
}

subtest "Multi-process EC results exclude incompatible curves" => sub {
    plan skip_all => "Multi option is not supported by this OpenSSL build"
        if $^O =~ /^(VMS|MSWin32)$/;
    plan skip_all => "EC and ECX support are required"
        if disabled("ec", "ecx");

    local $ENV{OPENSSL_CONF} = srctop_file("test", "default.cnf");
    local $ENV{OPENSSL_MODULES} = bldtop_dir("providers");

    foreach my $test (
        [ "ecdsa", "EC", "X25519|X448" ],
        [ "ecdh", "ecdh", "Ed25519|Ed448" ],
    ) {
        my ($algorithm, $label, $incompatible) = @$test;
        my $stdout = "speed-multi-ec.out";

        ok(run(app(['openssl', 'speed', '-testmode', '-multi', 2, $algorithm],
                   stdout => $stdout)),
           "multi-process $algorithm succeeds");
        open my $fh, '<', $stdout or die "Cannot open $stdout: $!";
        my $output = do { local $/; <$fh> };
        close $fh;
        unlink $stdout;

        like($output, qr/^\s*\d+ bits \Q$label\E \(prime256v1\)/m,
             "$algorithm reports a compatible curve");
        unlike($output, qr/^\s*\d+ bits \Q$label\E \((?:$incompatible)\)/m,
               "$algorithm does not report incompatible curves");
    }
    done_testing();
};

subtest "Simple test of all speed algorithms" => sub {
    local $ENV{OPENSSL_CONF} = srctop_file("test", "default.cnf");
    local $ENV{OPENSSL_MODULES} = bldtop_dir("providers");
    my $stderr = "speed-default.err";

    ok(run(app(['openssl', 'speed', '-testmode', '-mr'], stderr => $stderr)),
       "default algorithms succeed");
    open my $fh, '<', $stderr or die "Cannot open $stderr: $!";
    my $output = do { local $/; <$fh> };
    close $fh;
    unlink $stderr;

    unlike($output, qr/(?:sign|verify) setup failure|ECDH key generation failure/,
           "default selections do not attempt incompatible EC operations");

    foreach my $operation (
        [ "ec", "prime256v1", 7, 8, 9 ],
        [ "ecx", "Ed25519", 7, 8 ],
        [ "ecx", "Ed448", 7, 8 ],
        [ "ecx", "X25519", 9 ],
        [ "ecx", "X448", 9 ],
        [ "sm2", "SM2", 7, 8, 9 ],
    ) {
        my ($feature, $name, @tags) = @$operation;

        SKIP: {
            # Default EC benchmarks are gated on ECX support.
            skip "Default $name benchmarks are disabled", scalar @tags
                if disabled($feature) || disabled("ecx");

            foreach my $tag (@tags) {
                like($output, qr/^\+R$tag:1:\Q$name\E:/m,
                     "$name completes operation R$tag exactly once");
            }
        }
    }
    done_testing();
};

# Exercise options with small symmetric and public-key selections rather than
# repeating the expensive default selection. Test mode reports operation errors.


SKIP: {
    skip "Multi option is not supported by this OpenSSL build", 1
       if $^O =~ /^(VMS|MSWin32)$/;

    ok(run(app(['openssl', 'speed', '-testmode', '-multi', 2,
                'sha256', 'rsa2048'])),
           "Test the multi option");
}

ok(run(app(['openssl', 'speed', '-testmode', '-misalign', 1,
            'sha256', 'rsa2048'])),
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

ok(run(app(['openssl', 'speed', '-testmode', '-mr', 'sha256', 'rsa2048'])),
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

    ok(run(app(['openssl', 'speed', '-testmode', '-async_jobs', '1',
                'sha256', 'rsa2048'])),
        "Test the async_jobs option");
}

SKIP: {
    skip "Mlock option is not supported by this OpenSSL build", 1
       if $^O !~ /^(linux|MSWin32)$/;

       ok(run(app(['openssl', 'speed', '-testmode', '-mlock',
                   'sha256', 'rsa2048'])),
              "Test the mlock option");
}

#We don't expect these options to have an effect in testmode but we at least
#test that the option parsing works ok
ok(run(app(['openssl', 'speed', '-testmode', '-seconds', 1, '-bytes', 16,
            '-elapsed', 'sha256', 'rsa2048'])),
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
