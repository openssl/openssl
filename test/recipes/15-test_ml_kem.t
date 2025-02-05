#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use File::Copy;
use File::Compare qw/compare_text compare/;
use OpenSSL::Glob;
use OpenSSL::Test qw/:DEFAULT data_file srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;

setup("test_ml_kem");

my @algs = qw(512 768 1024);
my @formats = qw(seed-priv priv-only seed-only priv-oqs pair-oqs);

plan skip_all => "ML-KEM isn't supported in this build"
    if disabled("ml-kem");

plan tests => 168;
my $seed = join ("", map {sprintf "%02x", $_} (0..63));
my $ikme = join ("", map {sprintf "%02x", $_} (0..31));

foreach my $alg (@algs) {
    my $pub = sprintf("pub-%s.pem", $alg);
    my %formats = map { ($_, sprintf("prv-%s-%s.pem", $alg, $_)) } @formats;

    # 11 tests
    my $i = 0;
    my $in0 = data_file($pub);
    my $der0 = sprintf("pub-%s.%d.der", $alg, $i++);
    ok(run(app(['openssl', 'pkey', '-pubin', '-in', $in0,
                '-outform', 'DER', '-out', $der0])));
    foreach my $f (keys %formats) {
        my $k = $formats{$f};
        my %pruned = %formats;
        delete $pruned{$f};
        my $rest = join(", ", keys %pruned);
        my $in = data_file($k);
        my $der = sprintf("pub-%s.%d.der", $alg, $i);
        #
        # Compare expected DER public key with DER public key of private
        ok(run(app(['openssl', 'pkey', '-in', $in, '-pubout',
                    '-outform', 'DER', '-out', $der])));
        ok(!compare($der0, $der),
            sprintf("pubkey DER match: %s, %s", $alg, $f));
        #
        # Compare expected PEM private key with regenerated key
        my $pem = sprintf("prv-%s-%s.%d.pem", $alg, $f, $i++);
        ok(run(app(['openssl', 'genpkey', '-out', $pem,
                    '-pkeyopt', "hexseed:$seed", '-algorithm', "ml-kem-$alg",
                    '-provparam', "ml-kem.output_formats=$f"])));
        ok(!compare($in, $pem),
            sprintf("prvkey PEM match: %s, %s", $alg, $f));

        ok(run(app(['openssl', 'pkey', '-in', $in, '-noout',
                     '-provparam', "ml-kem.input_formats=$f"])));
        ok(!run(app(['openssl', 'pkey', '-in', $in, '-noout',
                     '-provparam', "ml-kem.input_formats=$rest"])));
    }

    # 13 tests
    # Check encap/decap ciphertext and shared secrets
    $i = 0;
    my $refct = sprintf("ct-%s.dat", $alg);
    my $refss = sprintf("ss-%s.dat", $alg);
    my $ct = sprintf("ct-%s.%d.dat", $alg, $i);
    my $ss0 = sprintf("ss-%s.%d.dat", $alg, $i++);
    ok(run(app(['openssl', 'pkeyutl', '-encap', '-inkey', $in0,
                '-pkeyopt', "hexikme:$ikme", '-secret',
                $ss0, '-out', $ct])));
    ok(!compare($ct, data_file($refct)),
        sprintf("reference ciphertext match: %s", $pub));
    ok(!compare($ss0, data_file($refss)),
        sprintf("reference secret match: %s", $pub));
    while (my ($f, $k) = each %formats) {
        my $in = data_file($k);
        my $ss = sprintf("ss-%s.%d.dat", $alg, $i++);
        ok(run(app(['openssl', 'pkeyutl', '-decap', '-inkey', $in,
                    '-in', $ct, '-secret', $ss])));
        ok(!compare($ss0, $ss),
            sprintf("shared secret match: %s with %s", $alg, $f));
    }

    # 6 tests
    # Test keygen seed suppression via the command-line and config file.
    my $seedless = sprintf("seedless-%s.gen.cli.pem", $alg);
    ok(run(app(['openssl', 'genpkey', '-provparam', 'ml-kem.retain_seed=no',
                '-algorithm', "ml-kem-$alg", '-pkeyopt', "hexseed:$seed",
                '-out', $seedless])));
    ok(!compare(data_file($formats{'priv-only'}), $seedless),
        sprintf("seedless via cli key match: %s", $alg));
    {
        local $ENV{'OPENSSL_CONF'} = data_file("ml-kem.cnf");
        local $ENV{'RETAIN_SEED'} = "no";
        $seedless = sprintf("seedless-%s.gen.cnf.pem", $alg);
        ok(run(app(['openssl', 'genpkey',
                    '-algorithm', "ml-kem-$alg", '-pkeyopt', "hexseed:$seed",
                    '-out', $seedless])));
        ok(!compare(data_file($formats{'priv-only'}), $seedless),
            sprintf("seedless via config match: %s", $alg));

        my $seedfull = sprintf("seedfull-%s.gen.conf+cli.pem", $alg);
        ok(run(app(['openssl', 'genpkey', '-provparam', 'ml-kem.retain_seed=yes',
                    '-algorithm', "ml-kem-$alg", '-pkeyopt', "hexseed:$seed",
                    '-out', $seedfull])));
        ok(!compare(data_file($formats{'seed-priv'}), $seedfull),
            sprintf("seedfull via cli vs. conf key match: %s", $alg));
    }

    # 6 tests
    # Test decoder seed suppression via the config file and command-line.
    $seedless = sprintf("seedless-%s.dec.cli.pem", $alg);
    ok(run(app(['openssl', 'pkey', '-provparam', 'ml-kem.retain_seed=no',
                '-in', data_file($formats{'seed-only'}), '-out', $seedless])));
    ok(!compare(data_file($formats{'priv-only'}), $seedless),
        sprintf("seedless via provparam key match: %s", $alg));
    {
        local $ENV{'OPENSSL_CONF'} = data_file("ml-kem.cnf");
        local $ENV{'RETAIN_SEED'} = "no";
        $seedless = sprintf("seedless-%s.dec.cnf.pem", $alg);
        ok(run(app(['openssl', 'pkey',
                    '-in', data_file($formats{'seed-only'}), '-out', $seedless])));
        ok(!compare(data_file($formats{'priv-only'}), $seedless),
            sprintf("seedless via config match: %s", $alg));

        my $seedfull = sprintf("seedfull-%s.dec.conf+cli.pem", $alg);
        ok(run(app(['openssl', 'pkey', '-provparam', 'ml-kem.retain_seed=yes',
                    '-in', data_file($formats{'seed-only'}), '-out', $seedfull])));
        ok(!compare(data_file($formats{'seed-priv'}), $seedfull),
            sprintf("seedfull via cli vs. conf key match: %s", $alg));
    }
}
