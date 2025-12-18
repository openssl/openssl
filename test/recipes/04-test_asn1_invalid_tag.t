#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# Tests for issue #28424: Invalid non-minimal tag encodings
#
# This test suite includes:
#  - Low-level API tests (via asn1_invalid_tag_test C program)
#  - Command-line interface tests (OpenSSL CLI tools)
#

use strict;
use warnings;

use File::Spec;
use File::Temp qw(tempfile);
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_file/;
use OpenSSL::Test::Utils;

setup("test_asn1_invalid_tag");

plan tests => 10;

#
# Test 1: Run low-level API tests
#
ok(run(test(['asn1_invalid_tag_test'])),
   "asn1_invalid_tag_test - low-level API tests");

#
# Command-line interface tests
#

# Paths to test certificates
my $invalid_cert_pem = srctop_file("test", "recipes", "04-test_asn1_invalid_tag_cli_data", "test_cert_28424.pem");

#
# Test 2: openssl asn1parse should reject invalid certificate
#
ok(!run(app(['openssl', 'asn1parse',
             '-in', $invalid_cert_pem,
             '-inform', 'PEM'])),
   "asn1parse rejects invalid certificate");

#
# Test 3: Check that asn1parse error mentions invalid BER tag encoding
#
{
    my $errfile = "asn1parse-err.txt";
    run(app(['openssl', 'asn1parse',
             '-in', $invalid_cert_pem,
             '-inform', 'PEM'],
            stderr => $errfile));
    open my $fh, '<', $errfile or die "Cannot open $errfile: $!";
    my $output = do { local $/; <$fh> };
    close $fh;
    unlink $errfile;
    like($output, qr/invalid ber tag encoding/i,
         "asn1parse error message mentions 'invalid ber tag encoding'");
}

#
# Test 4: openssl x509 -text should reject invalid certificate
#
ok(!run(app(['openssl', 'x509',
             '-in', $invalid_cert_pem,
             '-text',
             '-noout'])),
   "x509 -text rejects invalid certificate");

#
# Test 5: openssl x509 -subject should reject invalid certificate
#
ok(!run(app(['openssl', 'x509',
             '-in', $invalid_cert_pem,
             '-subject',
             '-noout'])),
   "x509 -subject rejects invalid certificate");

#
# Test 6: openssl x509 -dates should reject invalid certificate
#
ok(!run(app(['openssl', 'x509',
             '-in', $invalid_cert_pem,
             '-dates',
             '-noout'])),
   "x509 -dates rejects invalid certificate");

#
# Test 7: openssl x509 -fingerprint should reject invalid certificate
#
ok(!run(app(['openssl', 'x509',
             '-in', $invalid_cert_pem,
             '-fingerprint',
             '-noout'])),
   "x509 -fingerprint rejects invalid certificate");

#
# Test 8: openssl verify should reject invalid certificate
#
ok(!run(app(['openssl', 'verify',
             $invalid_cert_pem])),
   "verify rejects invalid certificate");

#
# Test 9: Verify error output from x509 command contains expected message
#
{
    my $errfile = "x509-err.txt";
    run(app(['openssl', 'x509',
             '-in', $invalid_cert_pem,
             '-text',
             '-noout'],
            stderr => $errfile));
    open my $fh, '<', $errfile or die "Cannot open $errfile: $!";
    my $output = do { local $/; <$fh> };
    close $fh;
    unlink $errfile;
    like($output, qr/(unable to load certificate|Could not find certificate)/i,
         "x509 error message indicates certificate cannot be loaded");
}

#
# Test 10: Test conversion attempt from PEM to DER should fail
#
{
    my ($der_fh, $der_file) = tempfile(SUFFIX => '.der', UNLINK => 1);
    close($der_fh);

    ok(!run(app(['openssl', 'x509',
                 '-in', $invalid_cert_pem,
                 '-outform', 'DER',
                 '-out', $der_file])),
       "x509 format conversion to DER fails for invalid certificate");
}
