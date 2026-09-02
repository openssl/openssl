#! /usr/bin/env perl
# Copyright 2015-2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_dsa");

plan skip_all => 'DSA is not supported in this build' if disabled('dsa');
plan tests => 11;

require_ok(srctop_file('test','recipes','tconversion.pl'));

ok(run(test(["dsatest"])), "running dsatest");
ok(run(test(["dsa_no_digest_size_test"])),
   "running dsa_no_digest_size_test");

subtest "dsa conversions using 'openssl dsa' -- private key" => sub {
    tconversion( -type => 'dsa', -prefix => 'dsa-priv',
                 -in => srctop_file("test","testdsa.pem") );
};
subtest "dsa conversions using 'openssl dsa' -- public key" => sub {
    tconversion( -type => 'msb', -prefix => 'dsa-msb-pub',
                 -in => srctop_file("test","testdsapub.pem"),
                 -args => ["dsa", "-pubin", "-pubout"] );
};

subtest "dsa conversions using 'openssl pkey' -- private key PKCS#8" => sub {
    tconversion( -type => 'dsa', -prefix => 'dsa-pkcs8',
                 -in => srctop_file("test","testdsa.pem"),
                 -args => ["pkey"] );
};
subtest "dsa conversions using 'openssl pkey' -- public key" => sub {
    tconversion( -type => 'dsa', -prefix => 'dsa-pkey-pub',
                 -in => srctop_file("test","testdsapub.pem"),
                 -args => ["pkey", "-pubin", "-pubout"] );
};

SKIP: {
    skip "Skipping PVK conversion test", 1
        if disabled("rc4") || disabled("legacy") || disabled("pvkkdf");

    subtest "dsa conversions using 'openssl dsa' -- PVK" => sub {
        tconversion( -type => 'pvk', -prefix => 'dsa-pvk',
                     -in => srctop_file("test", "testdsa.pem"),
                     -args => ["dsa", "-passin", "pass:testpass",
                               "-passout", "pass:testpass",
                               "-provider", "default",
                               "-provider", "legacy"] );
    };
}

subtest "dsa -modulus prints the DSA public value" => sub {
    plan tests => 2;

    # The public value (y) of the committed testdsa.pem / testdsapub.pem
    # keypair, i.e. the "pub:" field of 'openssl pkey -text'.
    my $expected = "Public Key=CC99A07D9817BFF03BB09B183E9B19EB77ABECF192"
        . "C3A9FBA833DBE69EDB719A8E9777BB82736CEC6A8E4E2FAD0693ACC3D1456"
        . "5D62710B95B02CC6A5CF091EEF9C22F20193EBE114C45A0B5E54A645037E8"
        . "787FE01B3871508A25BDBF7C6B81428F89858F133FDB858C390C2EF7BCF7E"
        . "41D7C66578F792A2488C787EF7C7D41";

    my @priv = run(app(['openssl', 'dsa', '-modulus', '-noout',
                        '-in', srctop_file("test", "testdsa.pem")],
                       stderr => undef),
                   capture => 1);
    chomp @priv;
    ok(grep(/^\Q$expected\E$/, @priv),
       "-modulus prints the expected public value for a private key");

    my @pub = run(app(['openssl', 'dsa', '-pubin', '-modulus', '-noout',
                       '-in', srctop_file("test", "testdsapub.pem")],
                      stderr => undef),
                  capture => 1);
    chomp @pub;
    ok(grep(/^\Q$expected\E$/, @pub),
       "-modulus prints the expected public value for a public key");
};

subtest "dsa -text prints the key in text form" => sub {
    plan tests => 6;

    # The private (x) and public (y) values of the committed testdsa.pem /
    # testdsapub.pem keypair.  -text prints them as colon-separated hex; we
    # strip the formatting and compare against the known values so the actual
    # key material, not just the labels, is verified.
    my $priv_hex = "BF71D497B89755D0C5E41285D81F9577CC3DF8C2";
    my $pub_hex = "CC99A07D9817BFF03BB09B183E9B19EB77ABECF192C3A9FBA833DBE"
        . "69EDB719A8E9777BB82736CEC6A8E4E2FAD0693ACC3D14565D62710B95B02CC"
        . "6A5CF091EEF9C22F20193EBE114C45A0B5E54A645037E8787FE01B3871508A2"
        . "5BDBF7C6B81428F89858F133FDB858C390C2EF7BCF7E41D7C66578F792A2488"
        . "C787EF7C7D41";

    my @priv = run(app(['openssl', 'dsa', '-text', '-noout',
                        '-in', srctop_file("test", "testdsa.pem")],
                       stderr => undef),
                   capture => 1);
    chomp @priv;
    my $priv_blob = uc join('', @priv);
    $priv_blob =~ s/[^0-9A-F]//g;
    ok(grep(/^Private-Key: \(1024 bit\)$/, @priv),
       "-text prints the private key header");
    ok(index($priv_blob, $priv_hex) >= 0,
       "-text prints the expected private value");
    ok(index($priv_blob, $pub_hex) >= 0,
       "-text prints the expected public value for a private key");

    my @pub = run(app(['openssl', 'dsa', '-pubin', '-text', '-noout',
                       '-in', srctop_file("test", "testdsapub.pem")],
                      stderr => undef),
                  capture => 1);
    chomp @pub;
    my $pub_blob = uc join('', @pub);
    $pub_blob =~ s/[^0-9A-F]//g;
    ok(grep(/^Public-Key: \(1024 bit\)$/, @pub),
       "-text prints the public key header");
    ok(index($pub_blob, $pub_hex) >= 0,
       "-text prints the expected public value for a public key");
    ok(!grep(/^priv:/, @pub),
       "-text does not print a private component for a public key");
};

subtest "dsa PVK output is rejected for public key input" => sub {
    plan tests => 1;

    # Note: -noout would short-circuit before the format check, so request
    # an actual encoding to reach the PVK-with-public-key rejection.
    ok(!run(app(['openssl', 'dsa', '-pubin', '-outform', 'PVK',
                 '-in', srctop_file("test", "testdsapub.pem"),
                 '-out', 'dsa-pubin.pvk'])),
       "-outform PVK with -pubin is rejected");
};
