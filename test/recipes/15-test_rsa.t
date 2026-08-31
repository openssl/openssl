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
use OpenSSL::Test qw/:DEFAULT srctop_file with/;
use OpenSSL::Test::Utils;

setup("test_rsa");

plan tests => 19;

require_ok(srctop_file('test', 'recipes', 'tconversion.pl'));

ok(run(test(["rsa_test"])), "running rsatest");

run_rsa_tests("pkey");

run_rsa_tests("rsa");

SKIP: {
    skip "RSA is not supported in this build", 3 if disabled("rsa");

    subtest "rsa -modulus prints the RSA modulus" => sub {
        plan tests => 2;

        # The modulus (n) of the committed testrsa.pem / testrsapub.pem keypair.
        my $expected = "Modulus=AADB7AA92E464F15711996166B4FF8BBE2301DFEE9D8"
            . "B3596DC3C1A7DFCE7C87180170509FC84EFD17B5BB02CA5DD0A3228686B38"
            . "0CB746F3CAE4CDFC8AE5D3D";

        my @priv = run(app(['openssl', 'rsa', '-modulus', '-noout',
                            '-in', srctop_file("test", "testrsa.pem")],
                           stderr => undef),
                       capture => 1);
        chomp @priv;
        ok(grep(/^\Q$expected\E$/, @priv),
           "-modulus prints the expected modulus for a private key");

        my @pub = run(app(['openssl', 'rsa', '-pubin', '-modulus', '-noout',
                           '-in', srctop_file("test", "testrsapub.pem")],
                          stderr => undef),
                      capture => 1);
        chomp @pub;
        ok(grep(/^\Q$expected\E$/, @pub),
           "-modulus prints the expected modulus for a public key");
    };

    subtest "rsa -text prints the key in text form" => sub {
        plan tests => 6;

        # The modulus (n) and private exponent (d) of the committed
        # testrsa.pem keypair.  -text prints them as colon-separated hex; we
        # strip the formatting and compare against the known values so the
        # actual key material, not just the labels, is verified.
        my $modulus = "AADB7AA92E464F15711996166B4FF8BBE2301DFEE9D8B3596DC3"
            . "C1A7DFCE7C87180170509FC84EFD17B5BB02CA5DD0A3228686B380CB746F"
            . "3CAE4CDFC8AE5D3D";
        my $priv_exp = "677727CDA1D733F6F119A479091D51AC3D6A1410157E840588E1"
            . "FDB8F26031AA00BA84048AC3C755C64329C3AFE30120EBF4C89C02170671"
            . "2282DAAF473BB2A1";

        my @priv = run(app(['openssl', 'rsa', '-text', '-noout',
                            '-in', srctop_file("test", "testrsa.pem")],
                           stderr => undef),
                       capture => 1);
        chomp @priv;
        my $priv_blob = uc join('', @priv);
        $priv_blob =~ s/[^0-9A-F]//g;
        ok(grep(/^Private-Key: \(512 bit, 2 primes\)$/, @priv),
           "-text prints the private key header");
        ok(index($priv_blob, $modulus) >= 0,
           "-text prints the expected modulus for a private key");
        ok(index($priv_blob, $priv_exp) >= 0,
           "-text prints the expected private exponent");

        my @pub = run(app(['openssl', 'rsa', '-pubin', '-text', '-noout',
                           '-in', srctop_file("test", "testrsapub.pem")],
                          stderr => undef),
                      capture => 1);
        chomp @pub;
        my $pub_blob = uc join('', @pub);
        $pub_blob =~ s/[^0-9A-F]//g;
        ok(grep(/^Public-Key: \(512 bit\)$/, @pub),
           "-text prints the public key header");
        ok(index($pub_blob, $modulus) >= 0,
           "-text prints the expected modulus for a public key");
        ok(!grep(/privateExponent/, @pub),
           "-text does not print a private exponent for a public key");
    };

    subtest "rsa error cases" => sub {
        plan tests => 20;

        my $privkey = srctop_file("test", "testrsa.pem");
        my $pubkey = srctop_file("test", "testrsapub.pem");

        rsa_fails("invalid input format should fail",
                  qr/Invalid format "BAD" for option -inform/,
                  '-inform', 'BAD', '-in', $privkey);
        rsa_fails("invalid output format should fail",
                  qr/Invalid format "BAD" for option -outform/,
                  '-outform', 'BAD', '-in', $privkey);
        rsa_fails("extra positional argument should fail",
                  qr/Extra option: "extra"/,
                  '-in', $privkey, 'extra');
        rsa_fails("unknown cipher option should fail",
                  qr/Unknown option or cipher: badcipher/,
                  '-badcipher', '-in', $privkey);
        rsa_fails("invalid passin argument should fail",
                  qr/Error getting passwords/,
                  '-passin', 'bad:pass', '-in', $privkey);
        rsa_fails("checking a public key should fail",
                  qr/Only private keys can be checked/,
                  '-check', '-pubin', '-in', $pubkey);
        rsa_fails("unsupported output format should fail",
                  qr/bad output format specified for outfile/,
                  '-in', $privkey, '-outform', 'NSS', '-out', 'rsa-nss.out');
        rsa_fails("PVK output for public key input should fail",
                  qr/PVK form impossible with public key input/,
                  '-pubin', '-in', $pubkey, '-outform', 'PVK',
                  '-out', 'rsa-pvk.out');

        my $garbage = "garbage.pem";
        open(my $fh, '>', $garbage) or die "Cannot write $garbage: $!";
        print $fh "not a valid RSA key file\n";
        close($fh);
        rsa_fails("loading garbage key file should fail",
                  qr/Could not find or decode private key/,
                  '-in', $garbage, '-noout');

        SKIP: {
            my $nonrsa = !disabled("ec")
                ? srctop_file("test", "testec-p256.pem")
                : !disabled("dsa")
                    ? srctop_file("test", "testdsa.pem")
                    : undef;

            skip "No non-RSA key type available in this build", 2
                if !defined $nonrsa;

            rsa_fails("loading a non-RSA key should fail",
                      qr/Not an RSA key/,
                      '-in', $nonrsa, '-noout');
        }
    };
}

# Helper: run rsa expecting a non-zero (failure) exit code, and check that
# stderr matches a regular expression.
sub rsa_fails {
    my ($testtext, $re, @args) = @_;

    my $stderr_file = "rsa_err.txt";
    my $err = '';

    with({ exit_checker => sub { return shift != 0; } },
        sub {
            ok(run(app(['openssl', 'rsa', @args], stderr => $stderr_file)),
               $testtext);
        });

    if (open(my $fh, '<', $stderr_file)) {
        $err = do { local $/; <$fh> };
        close($fh);
    }
    ok($err =~ $re, "$testtext: stderr matches");
    unlink($stderr_file) if -f $stderr_file;
}

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
