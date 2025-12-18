#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# Tests for issue #28424: Invalid non-minimal tag encodings
# This tests OpenSSL CLI tools to ensure they reject invalid certificates
#

use strict;
use warnings;

use File::Spec;
use File::Temp qw(tempfile);
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_file/;
use OpenSSL::Test::Utils;

setup("test_asn1_invalid_tag_cli");

plan tests => 15;

# Paths to test certificates
my $invalid_cert_pem = srctop_file("test", "recipes", "04-test_asn1_invalid_tag_cli_data", "test_cert_28424.pem");

# Create temporary valid certificate for regression testing
my ($valid_fh, $valid_cert_pem) = tempfile(SUFFIX => '.pem', UNLINK => 1);
print $valid_fh <<'EOF';
-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIUOo6s1qShz1pDHNAux5oSEC2RMcwwDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEVGVzdDAeFw0yNTEyMTgwMjI2MDBaFw0yNTEyMTkwMjI2
MDBaMA8xDTALBgNVBAMMBFRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDq+p4GuB+i5fZefKbV0QhkT71uWA89nFgpcaz0A3gnqsQwJVtgZXLi7hW0
x4b7cql7oKNuyheVRku4VXOv0GxtRu9/8dEToHY2LT2zHC7lVq2PiZbQkjdl4lG/
wVffn/Lm60+wJQ2Zu9NMSJBp3AaEz79pzFrz1TnSEW++aDY7Z25EqLp6g2tu65qi
rCwJjoyaYwSwXGEbned0MY+Faw5VXO6BGpFZ4OEcFY+Pw7dK93jzsPf226aae6oE
bTFARf0RVZ7Vd4a82afr4gzMkQx61UzokMspzd7oFSuRzZr2i1WqxZlC8jHWWdUk
FubRROAZDHq/CcJa4X3AfJ8D+mx7AgMBAAGjUzBRMB0GA1UdDgQWBBRz0dSTUJcS
526yqAflndbVuOqUETAfBgNVHSMEGDAWgBRz0dSTUJcS526yqAflndbVuOqUETAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDZJp6FjRBZXLiGi1+l
vFdSlIRaoviGEYaMzueEQqVk7a/smuM96HBFhWqHYndpfWqptzGH6Tf6x+mECh/I
5Z++Em6a4DHRza9iPPQsv8dMf3JPAKzxhliWCghPKap7lhjrZccBow//uqQ5ueLh
//WNFUdybuK5bHRTdPNmKHceuPCCUZfqhchGIQRV1Ls3JZ/mqggh2BTazK5t1Dz3
dSQBSrypvsEJV8GzyWJT1t/wrBnu7GvOdpKbjMpdGo32DZYZhuU5WHgNe74auRkE
A6eEd0OjzMe/OKncQN0Y8gkIF/BIb1+/NynZMqXnlif1lOyaOdcFHa1fU7J8hvKr
aLav
-----END CERTIFICATE-----
EOF
close($valid_fh);

#
# Test 1: openssl asn1parse should reject invalid certificate
#
ok(!run(app(['openssl', 'asn1parse',
             '-in', $invalid_cert_pem,
             '-inform', 'PEM'])),
   "asn1parse rejects invalid certificate");

#
# Test 2: Check that asn1parse error mentions invalid BER tag encoding
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
# Test 3: openssl x509 -text should reject invalid certificate
#
ok(!run(app(['openssl', 'x509',
             '-in', $invalid_cert_pem,
             '-text',
             '-noout'])),
   "x509 -text rejects invalid certificate");

#
# Test 4: openssl x509 -subject should reject invalid certificate
#
ok(!run(app(['openssl', 'x509',
             '-in', $invalid_cert_pem,
             '-subject',
             '-noout'])),
   "x509 -subject rejects invalid certificate");

#
# Test 5: openssl x509 -dates should reject invalid certificate
#
ok(!run(app(['openssl', 'x509',
             '-in', $invalid_cert_pem,
             '-dates',
             '-noout'])),
   "x509 -dates rejects invalid certificate");

#
# Test 6: openssl x509 -fingerprint should reject invalid certificate
#
ok(!run(app(['openssl', 'x509',
             '-in', $invalid_cert_pem,
             '-fingerprint',
             '-noout'])),
   "x509 -fingerprint rejects invalid certificate");

#
# Test 7: openssl verify should reject invalid certificate
#
ok(!run(app(['openssl', 'verify',
             $invalid_cert_pem])),
   "verify rejects invalid certificate");

#
# Test 8: Verify error output from x509 command contains expected message
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
# REGRESSION TESTS: Verify valid certificates still work
#

#
# Test 9: asn1parse should accept valid certificate
#
ok(run(app(['openssl', 'asn1parse',
            '-in', $valid_cert_pem,
            '-inform', 'PEM',
            '-noout'])),
   "asn1parse accepts valid certificate");

#
# Test 10: openssl x509 -text should accept valid certificate
#
ok(run(app(['openssl', 'x509',
            '-in', $valid_cert_pem,
            '-text',
            '-noout'])),
   "x509 -text accepts valid certificate");

#
# Test 11: openssl x509 -subject should work with valid certificate
#
{
    my $outfile = "x509-subject.txt";
    ok(run(app(['openssl', 'x509',
                '-in', $valid_cert_pem,
                '-subject',
                '-noout'],
               stdout => $outfile)),
       "x509 -subject works with valid certificate");
    open my $fh, '<', $outfile or die "Cannot open $outfile: $!";
    my $output = do { local $/; <$fh> };
    close $fh;
    unlink $outfile;
    like($output, qr/subject.*CN.*=.*Test/i,
         "x509 -subject output contains expected CN=Test");
}

#
# Test 13: openssl x509 -dates should work with valid certificate
#
{
    my $outfile = "x509-dates.txt";
    ok(run(app(['openssl', 'x509',
                '-in', $valid_cert_pem,
                '-dates',
                '-noout'],
               stdout => $outfile)),
       "x509 -dates works with valid certificate");
    open my $fh, '<', $outfile or die "Cannot open $outfile: $!";
    my $output = do { local $/; <$fh> };
    close $fh;
    unlink $outfile;
    like($output, qr/(notBefore|notAfter)/i,
         "x509 -dates output contains notBefore/notAfter");
}

#
# Test 15: Test conversion attempt from PEM to DER should fail
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
