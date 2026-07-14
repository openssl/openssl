#! /usr/bin/env perl
# Copyright 2015-2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use File::Compare qw(compare);
use OpenSSL::Test qw/:DEFAULT srctop_file data_file/;
use OpenSSL::Test::Utils;

setup("test_ec");

plan skip_all => 'EC is not supported in this build' if disabled('ec');

plan tests => 19;

my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);

require_ok(srctop_file('test','recipes','tconversion.pl'));

ok(run(test(["ectest"])), "running ectest");

# TODO: remove these when the 'ec' app is removed.
# Also consider moving this to the 20-25 test section because it is testing
# the command line tool in addition to the algorithm.
subtest 'EC conversions -- private key' => sub {
    tconversion( -type => 'ec', -prefix => 'ec-priv',
                 -in => srctop_file("test","testec-p256.pem") );
};

SKIP: {
    skip "SM2 is not supported by this OpenSSL build", 1
        if disabled("sm2");
    subtest 'EC conversions -- private key' => sub {
        tconversion( -type => 'ec', -prefix => 'sm2-priv',
                     -in => srctop_file("test","testec-sm2.pem") );
    };
}

subtest 'EC conversions -- private key PKCS#8' => sub {
    tconversion( -type => 'ec', -prefix => 'ec-pkcs8',
                 -in => srctop_file("test","testec-p256.pem"),
                 -args => "pkey" );
};
subtest 'EC conversions -- public key' => sub {
    tconversion( -type => 'ec', -prefix => 'ec-pub',
                 -in => srctop_file("test","testecpub-p256.pem"),
                 -args => [ "ec", "-pubin", "-pubout" ] );
};

subtest 'PKEY conversions -- private key' => sub {
    tconversion( -type => 'pkey', -prefix => 'ec-pkey-priv',
                 -in => srctop_file("test","testec-p256.pem") );
};
subtest 'PKEY conversions -- private key PKCS#8' => sub {
    tconversion( -type => 'pkey', -prefix => 'ec-pkey-pkcs8',
                 -in => srctop_file("test","testec-p256.pem"),
                 -args => "pkey" );
};
subtest 'PKEY conversions -- public key' => sub {
    tconversion( -type => 'pkey', -prefix => 'ec-pkey-pub',
                 -in => srctop_file("test","testecpub-p256.pem"),
                 -args => [ "pkey", "-pubin", "-pubout" ] );
};

SKIP: {
    skip "ECX is not supported by this OpenSSL build", 6
        if disabled("ecx");
    subtest 'Ed25519 conversions -- private key' => sub {
        tconversion( -type => "pkey", -prefix => "ed25519-pkey-priv",
                     -in => srctop_file("test", "tested25519.pem") );
    };
    subtest 'Ed25519 conversions -- private key PKCS#8' => sub {
        tconversion( -type => "pkey", -prefix => "ed25519-pkey-pkcs8",
                     -in => srctop_file("test", "tested25519.pem"),
                     -args => ["pkey"] );
    };
    subtest 'Ed25519 conversions -- public key' => sub {
        tconversion( -type => "pkey", -prefix => "ed25519-pkey-pub",
                     -in => srctop_file("test", "tested25519pub.pem"),
                     -args => ["pkey", "-pubin", "-pubout"] );
    };
    subtest 'Ed448 conversions -- private key' => sub {
        tconversion( -type => "pkey", -prefix => "ed448-pkey-priv",
                     -in => srctop_file("test", "tested448.pem") );
    };
    subtest 'Ed448 conversions -- private key PKCS#8' => sub {
        tconversion( -type => "pkey", -prefix => "ed448-pkey-pkcs8",
                     -in => srctop_file("test", "tested448.pem"),
                     -args => ["pkey"] );
    };
    subtest 'Ed448 conversions -- public key' => sub {
        tconversion( -type => "pkey", -prefix => "ed448-pkey-pub",
                     -in => srctop_file("test", "tested448pub.pem"),
                     -args => ["pkey", "-pubin", "-pubout"] );
    };
}

subtest 'EC point conversion form (-conv_form)' => sub {
    plan tests => 6;

    my $key = srctop_file("test", "testec-p256.pem");

    ok(run(app(['openssl', 'ec', '-in', $key, '-pubout',
                '-outform', 'DER', '-out', 'ec-conv-unc.der'])),
       "writing public key with default (uncompressed) conversion form");
    ok(run(app(['openssl', 'ec', '-in', $key, '-pubout',
                '-conv_form', 'compressed',
                '-outform', 'DER', '-out', 'ec-conv-comp.der'])),
       "writing public key with compressed conversion form");
    ok((-s 'ec-conv-comp.der') < (-s 'ec-conv-unc.der'),
       "compressed point encoding is smaller than uncompressed");
    # The encodings are deterministic for a fixed key, so compare them
    # against the checked-in reference files.
    is(compare('ec-conv-unc.der', data_file('ec-conv-unc.der')), 0,
       "uncompressed encoding matches the reference file");
    is(compare('ec-conv-comp.der', data_file('ec-conv-comp.der')), 0,
       "compressed encoding matches the reference file");
    ok(!run(app(['openssl', 'ec', '-in', $key, '-noout',
                 '-conv_form', 'bogus'])),
       "an invalid conversion form is rejected");
};

subtest 'EC parameter encoding (-param_enc)' => sub {
    plan tests => 6;

    my $key = srctop_file("test", "testec-p256.pem");

    ok(run(app(['openssl', 'ec', '-in', $key, '-pubout', '-param_enc',
                'named_curve', '-outform', 'DER', '-out', 'ec-param-named.der'])),
       "writing public key with named_curve parameter encoding");
    ok(run(app(['openssl', 'ec', '-in', $key, '-pubout', '-param_enc',
                'explicit', '-outform', 'DER', '-out', 'ec-param-explicit.der'])),
       "writing public key with explicit parameter encoding");
    ok((-s 'ec-param-named.der') < (-s 'ec-param-explicit.der'),
       "named_curve encoding is smaller than explicit");
    # The encodings are deterministic for a fixed key, so compare them
    # against the checked-in reference files.
    is(compare('ec-param-named.der', data_file('ec-param-named.der')), 0,
       "named_curve encoding matches the reference file");
    is(compare('ec-param-explicit.der', data_file('ec-param-explicit.der')), 0,
       "explicit encoding matches the reference file");
    ok(!run(app(['openssl', 'ec', '-in', $key, '-noout',
                 '-param_enc', 'bogus'])),
       "an invalid parameter encoding is rejected");
};

subtest 'ec -text prints the key in text form' => sub {
    plan tests => 7;

    my $priv_key = srctop_file("test", "testec-p256.pem");
    my $pub_key = srctop_file("test", "testecpub-p256.pem");

    # The private (priv) and public (pub) values of the committed
    # testec-p256.pem / testecpub-p256.pem keypair.  -text prints them as
    # colon-separated hex; we strip the formatting and compare against the
    # known values so the actual key material, not just the labels, is checked.
    my $priv_hex = "36045F6C909612570C8C0113071FC809F6788084289C6AB003C60A"
        . "17B2D5ADAD";
    my $pub_hex = "04257C007484E23C571252C6912369E5CD33519FEFAAE85DFC5EB1FC"
        . "9BCB1FDBC0D0FB63A86F9494CEF823552D1EEF4A48A87E9B4970E03DCF262AD"
        . "4ACF598B6E9";

    # ec -text on the private key.
    my @priv = run(app(['openssl', 'ec', '-text', '-noout', '-in', $priv_key],
                       stderr => undef),
                   capture => 1);
    chomp @priv;
    my $priv_blob = uc join('', @priv);
    $priv_blob =~ s/[^0-9A-F]//g;
    ok(grep(/^Private-Key: \(256 bit field, 128 bit security level\)$/, @priv),
       "ec -text prints the private key header");
    ok(index($priv_blob, $priv_hex) >= 0,
       "ec -text prints the expected private value");
    ok(index($priv_blob, $pub_hex) >= 0,
       "ec -text prints the expected public value");
    ok(grep(/^ASN1 OID: prime256v1$/, @priv)
       && grep(/^NIST CURVE: P-256$/, @priv),
       "ec -text prints the curve identification");

    # ec -text on the public key.
    my @pub = run(app(['openssl', 'ec', '-pubin', '-text', '-noout',
                       '-in', $pub_key],
                      stderr => undef),
                  capture => 1);
    chomp @pub;
    my $pub_blob = uc join('', @pub);
    $pub_blob =~ s/[^0-9A-F]//g;
    ok(grep(/^Public-Key: \(256 bit field, 128 bit security level\)$/, @pub),
       "ec -text prints the public key header");
    ok(index($pub_blob, $pub_hex) >= 0,
       "ec -text prints the expected public value for a public key");
    ok(!grep(/^priv:/, @pub),
       "ec -text does not print a private component for a public key");
};

subtest 'Check loading of fips and non-fips keys' => sub {
    plan skip_all => "FIPS is disabled"
        if $no_fips;

    plan tests => 2;

    my $fipsconf = srctop_file("test", "fips-and-base.cnf");
    $ENV{OPENSSL_CONF} = $fipsconf;

    ok(!run(app(['openssl', 'pkey',
                 '-check', '-in', srctop_file("test", "testec-p112r1.pem")])),
        "Checking non-fips curve key fails in FIPS provider");

    ok(run(app(['openssl', 'pkey',
                '-provider', 'default',
                '-propquery', '?fips!=yes',
                '-check', '-in', srctop_file("test", "testec-p112r1.pem")])),
        "Checking non-fips curve key succeeds with non-fips property query");

    delete $ENV{OPENSSL_CONF};
}
