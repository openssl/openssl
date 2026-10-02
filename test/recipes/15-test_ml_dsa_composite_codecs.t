#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Compare qw/compare_text/;
use OpenSSL::Test qw(:DEFAULT srctop_dir bldtop_dir srctop_file data_file);
use OpenSSL::Test::Utils;

BEGIN {
    setup("test_ml_dsa_composite_codecs");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

plan skip_all => 'ML DSA Composite signatures are not supported in this build'
    if disabled('ml-dsa-composite');

my $no_ec = disabled('ec');

# Remove EC-dependent ml dsa composites when EC is disabled
my @ml_dsa_composite_pems = (
    [ "ML-DSA-65-RSA3072-PKCS15-SHA512", "testmldsacomposite65-rsa3072pkcs15",
      "draft-mldsa65-rsa3072pkcs15" ],
    [ "ML-DSA-65-ECDSA-P256-SHA512",     "testmldsacomposite65-ecdsa-p256",
      "draft-mldsa65-ecdsa-p256" ],
);
@ml_dsa_composite_pems = grep { $_->[0] !~ /ECDSA/ } @ml_dsa_composite_pems if $no_ec;

# 1 require_ok
# + N x (2 tconversion subtests + 2 text checks x 2 tests + 2 draft checks x 2 tests)
plan tests => 1 + @ml_dsa_composite_pems * 10;

require_ok(srctop_file('test','recipes','tconversion.pl'));

foreach my $entry (@ml_dsa_composite_pems) {
    my ($alg, $base, $draft) = @$entry;

    subtest "$alg conversions -- pkcs8" => sub {
        tconversion(-type   => "pkey",
                    -in     => data_file("${base}.pem"),
                    -args   => ["pkey"],
                    -prefix => "${base}-pkcs8");
    };

    subtest "$alg conversions -- pub" => sub {
        tconversion(-type   => "pkey",
                    -in     => data_file("${base}pub.pem"),
                    -args   => ["pkey", "-pubin", "-pubout"],
                    -prefix => "${base}-pub");
    };

    # Check text encoding of the draft keys
    foreach my $form (["private", "priv"], ["public", "pub"]) {
        my ($kind, $suffix) = @$form;
        my $out = "${draft}-${suffix}.out.txt";
        my @pubin = $suffix eq "pub" ? ("-pubin") : ();

        ok(run(app(['openssl', 'pkey', @pubin,
                    '-in', data_file("${draft}-${suffix}.pem"),
                    '-noout', '-text', '-out', $out])),
           "text form $kind key: $alg");
        ok(!compare_text(data_file("${draft}-${suffix}.txt"), $out),
           "text form $kind key matches reference: $alg");
    }

    # The draft's own PKCS#8 and SPKI encodings, from its test vectors.
    my $derived_pub = "${draft}-derived-pub.pem";
    ok(run(app(['openssl', 'pkey', '-in', data_file("${draft}-priv.pem"),
                '-pubout', '-out', $derived_pub])),
       "draft private key loads and yields a public key: $alg");
    ok(!compare_text(data_file("${draft}-pub.pem"), $derived_pub),
       "draft public key matches the one derived from its private key: $alg");

    my $reenc_priv = "${draft}-reenc-priv.pem";
    ok(run(app(['openssl', 'pkey', '-in', data_file("${draft}-priv.pem"),
                '-out', $reenc_priv])),
       "draft private key re-encodes: $alg");
    ok(!compare_text(data_file("${draft}-priv.pem"), $reenc_priv),
       "draft private key re-encodes to identical PKCS#8: $alg");
}
