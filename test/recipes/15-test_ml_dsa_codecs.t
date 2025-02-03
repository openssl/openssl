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

setup("test_ml_dsa_codecs");

my @algs = qw(44 65 87);
my @formats = qw(seed-priv priv-only seed-only oqskeypair bare-seed bare-priv);

plan skip_all => "ML-DSA isn't supported in this build"
    if disabled("ml-dsa");

plan tests => @algs * (16 + 10 * @formats);
my $seed = join ("", map {sprintf "%02x", $_} (0..31));
my $ikme = join ("", map {sprintf "%02x", $_} (0..31));

foreach my $alg (@algs) {
    my $pub = sprintf("pub-%s.pem", $alg);
    my %formats = map { ($_, sprintf("prv-%s-%s.pem", $alg, $_)) } @formats;

    # (1 + 6 * @formats) tests
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
                    '-pkeyopt', "hexseed:$seed", '-algorithm', "ml-dsa-$alg",
                    '-provparam', "ml-dsa.output_formats=$f"])));
        ok(!compare($in, $pem),
            sprintf("prvkey PEM match: %s, %s", $alg, $f));

        ok(run(app(['openssl', 'pkey', '-in', $in, '-noout',
                     '-provparam', "ml-dsa.input_formats=$f"])));
        ok(!run(app(['openssl', 'pkey', '-in', $in, '-noout',
                     '-provparam', "ml-dsa.input_formats=$rest"])));
    }

    # (1 + 2 * @formats) tests
    # Perform sign/verify PCT
    $i = 0;
    my $refsig = data_file(sprintf("sig-%s.dat", $alg));
    my $sig = sprintf("sig-%s.%d.dat", $alg, $i);
    ok(run(app([qw(openssl pkeyutl -verify -rawin -pubin -inkey),
                $in0, '-in', $der0, '-sigfile', $refsig],
               sprintf("Signature verify with pubkey: %s", $alg))));
    while (my ($f, $k) = each %formats) {
        my $sk = data_file($k);
        my $s = sprintf("sig-%s.%d.dat", $alg, $i++);
        ok(run(app([qw(openssl pkeyutl -sign -rawin -inkey), $sk, '-in', $der0,
                    qw(-pkeyopt deterministic:1 -out), $s])));
        ok(!compare($s, $refsig),
            sprintf("Signature blob match %s with %s", $alg, $f));
    }

    # 6 tests
    # Test keygen seed suppression via the command-line and config file.
    my $seedless = sprintf("seedless-%s.gen.cli.pem", $alg);
    ok(run(app([qw(openssl genpkey -provparam ml-dsa.retain_seed=no),
                '-algorithm', "ml-dsa-$alg", '-pkeyopt', "hexseed:$seed",
                '-out', $seedless])));
    ok(!compare(data_file($formats{'priv-only'}), $seedless),
        sprintf("seedless via cli key match: %s", $alg));
    {
        local $ENV{'OPENSSL_CONF'} = data_file("ml-dsa.cnf");
        local $ENV{'RETAIN_SEED'} = "no";
        $seedless = sprintf("seedless-%s.gen.cnf.pem", $alg);
        ok(run(app(['openssl', 'genpkey',
                    '-algorithm', "ml-dsa-$alg", '-pkeyopt', "hexseed:$seed",
                    '-out', $seedless])));
        ok(!compare(data_file($formats{'priv-only'}), $seedless),
            sprintf("seedless via config match: %s", $alg));

        my $seedfull = sprintf("seedfull-%s.gen.conf+cli.pem", $alg);
        ok(run(app(['openssl', 'genpkey', '-provparam', 'ml-dsa.retain_seed=yes',
                    '-algorithm', "ml-dsa-$alg", '-pkeyopt', "hexseed:$seed",
                    '-out', $seedfull])));
        ok(!compare(data_file($formats{'seed-priv'}), $seedfull),
            sprintf("seedfull via cli vs. conf key match: %s", $alg));
    }

    # 6 tests
    # Test decoder seed suppression via the config file and command-line.
    $seedless = sprintf("seedless-%s.dec.cli.pem", $alg);
    ok(run(app(['openssl', 'pkey', '-provparam', 'ml-dsa.retain_seed=no',
                '-in', data_file($formats{'seed-only'}), '-out', $seedless])));
    ok(!compare(data_file($formats{'priv-only'}), $seedless),
        sprintf("seedless via provparam key match: %s", $alg));
    {
        local $ENV{'OPENSSL_CONF'} = data_file("ml-dsa.cnf");
        local $ENV{'RETAIN_SEED'} = "no";
        $seedless = sprintf("seedless-%s.dec.cnf.pem", $alg);
        ok(run(app(['openssl', 'pkey',
                    '-in', data_file($formats{'seed-only'}), '-out', $seedless])));
        ok(!compare(data_file($formats{'priv-only'}), $seedless),
            sprintf("seedless via config match: %s", $alg));

        my $seedfull = sprintf("seedfull-%s.dec.conf+cli.pem", $alg);
        ok(run(app(['openssl', 'pkey', '-provparam', 'ml-dsa.retain_seed=yes',
                    '-in', data_file($formats{'seed-only'}), '-out', $seedfull])));
        ok(!compare(data_file($formats{'seed-priv'}), $seedfull),
            sprintf("seedfull via cli vs. conf key match: %s", $alg));
    }

    # 2 tests
    # Test decoder seed non-preference via the command-line.
    my $privpref = sprintf("privpref-%s.dec.cli.pem", $alg);
    ok(run(app(['openssl', 'pkey', '-provparam', 'ml-dsa.prefer_seed=no',
                '-in', data_file($formats{'seed-priv'}), '-out', $privpref])));
    ok(!compare(data_file($formats{'priv-only'}), $privpref),
        sprintf("seed non-preference via provparam key match: %s", $alg));

    # (2 * @formats) tests
    # Check text encoding
    while (my ($f, $k) = each %formats) {
        my $txt =  sprintf("prv-%s-%s.txt", $alg,
                            ($f =~ m{seed}) ? 'seed' : 'priv');
        my $out = sprintf("prv-%s-%s.txt", $alg, $f);
        ok(run(app(['openssl', 'pkey', '-in', data_file($k),
                    '-noout', '-text', '-out', $out])));
        ok(!compare(data_file($txt), $out),
            sprintf("text form private key: %s with %s", $alg, $f));
    }
}
