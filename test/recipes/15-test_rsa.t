#! /usr/bin/env perl
# Copyright 2015-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use File::Compare qw/compare/;
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_rsa");

plan tests => 16;

require_ok(srctop_file('test', 'recipes', 'tconversion.pl'));

ok(run(test(["rsa_test"])), "running rsatest");

run_rsa_tests("pkey");

run_rsa_tests("rsa");

sub run_rsa_tests {
    my $cmd = shift;

    ok(run(app([ 'openssl', $cmd, '-check', '-in', srctop_file('test', 'testrsa.pem'), '-noout'])),
           "$cmd -check" );

    SKIP: {
        skip "Skipping Deprecated rsa_x931_test", 1 if disabled("deprecated-3.0");
        ok(run(test(['rsa_x931_test'])), "RSA X931 test");
    };

    SKIP: {
         skip "Skipping $cmd conversion test", 3
             if disabled("rsa");

         subtest "$cmd conversions -- private key" => sub {
             tconversion( -type => $cmd, -prefix => "$cmd-priv",
                          -in => srctop_file("test", "testrsa.pem") );
         };
         subtest "$cmd conversions -- private key PKCS#8" => sub {
             tconversion( -type => $cmd, -prefix => "$cmd-pkcs8",
                          -in => srctop_file("test", "testrsa.pem"),
                          -args => ["pkey"] );
         };
    }

    SKIP: {
         skip "Skipping msblob conversion test", 1
             if disabled("rsa") || $cmd eq 'pkey';

         subtest "$cmd conversions -- public key" => sub {
             tconversion( -type => 'msb', -prefix => "$cmd-msb-pub",
                          -in => srctop_file("test", "testrsapub.pem"),
                          -args => ["rsa", "-pubin", "-pubout"] );
         };
    }
    SKIP: {
         skip "Skipping PVK conversion test", 1
             if disabled("rsa") || $cmd eq 'pkey' || disabled("rc4")
                || disabled ("legacy") || disabled("pvkkdf");

         subtest "$cmd conversions -- private key" => sub {
             tconversion( -type => 'pvk', -prefix => "$cmd-pvk",
                          -in => srctop_file("test", "testrsa.pem"),
                          -args => ["rsa", "-passin", "pass:testpass",
                                    "-passout", "pass:testpass",
                                    "-provider", "default",
                                    "-provider", "legacy"] );
         };
    }

    SKIP: {
         # -RSAPublicKey_in/-RSAPublicKey_out are specific to the rsa app and
         # select the PKCS#1 RSAPublicKey structure instead of the
         # SubjectPublicKeyInfo used by -pubin/-pubout.
         skip "Skipping RSAPublicKey conversion test", 1
             if disabled("rsa") || $cmd eq 'pkey';

         subtest "$cmd conversions -- RSAPublicKey (PKCS#1) public key" => sub {
             plan tests => 9;

             my $priv = srctop_file("test", "testrsa.pem");
             my $pub = srctop_file("test", "testrsapub.pem");

             my $rsapub = "$cmd-rsapub.pem";
             ok(run(app(['openssl', 'rsa', '-in', $priv, '-RSAPublicKey_out',
                         '-out', $rsapub])),
                "RSAPublicKey_out writes a public key");
             open(my $fh, '<', $rsapub);
             my @rsapub_pem = <$fh>;
             close($fh);
             ok(grep(/BEGIN RSA PUBLIC KEY/, @rsapub_pem),
                "RSAPublicKey_out uses the PKCS#1 RSA PUBLIC KEY header");

             # Re-encoding an RSAPublicKey input as RSAPublicKey is stable.
             my $rsapub2 = "$cmd-rsapub2.pem";
             ok(run(app(['openssl', 'rsa', '-in', $rsapub, '-RSAPublicKey_in',
                         '-RSAPublicKey_out', '-out', $rsapub2])),
                "RSAPublicKey_in reads an RSAPublicKey");
             is(compare($rsapub, $rsapub2), 0,
                "RSAPublicKey_in round-trips to an identical RSAPublicKey");

             # RSAPublicKey input re-encoded as SubjectPublicKeyInfo matches the
             # canonical SubjectPublicKeyInfo public key.
             my $spki1 = "$cmd-spki1.pem";
             my $spki2 = "$cmd-spki2.pem";
             ok(run(app(['openssl', 'rsa', '-in', $rsapub, '-RSAPublicKey_in',
                         '-pubout', '-out', $spki1])),
                "RSAPublicKey_in can be written as SubjectPublicKeyInfo");
             ok(run(app(['openssl', 'rsa', '-in', $pub, '-pubin', '-pubout',
                         '-out', $spki2])),
                "canonical SubjectPublicKeyInfo public key written");
             is(compare($spki1, $spki2), 0,
                "RSAPublicKey_in -pubout matches the SubjectPublicKeyInfo key");

             # Conversely, a SubjectPublicKeyInfo input written as RSAPublicKey
             # matches the RSAPublicKey extracted from the private key.
             my $rsapub3 = "$cmd-rsapub3.pem";
             ok(run(app(['openssl', 'rsa', '-in', $pub, '-pubin',
                         '-RSAPublicKey_out', '-out', $rsapub3])),
                "SubjectPublicKeyInfo input can be written as RSAPublicKey");
             is(compare($rsapub, $rsapub3), 0,
                "pubin -RSAPublicKey_out matches the extracted RSAPublicKey");
         };
    }
}
