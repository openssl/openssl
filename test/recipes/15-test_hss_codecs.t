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
use IO::File;
use OpenSSL::Glob;
use OpenSSL::Test qw/:DEFAULT data_file srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;

setup("test_hss_codecs");

my @algs = qw(n32 n24);

plan skip_all => "HSS isn't supported in this build"
    if disabled("hss");

plan tests => @algs * 12;

foreach my $alg (@algs) {
    my $in_der = data_file(sprintf("pub_%s.der", $alg));
    my $in_pem = data_file(sprintf("pub_%s.pem", $alg));
    my $out_der = sprintf("pub_%s_out.der", $alg);
    my $out_pem = sprintf("pub_%s_out.pem", $alg);
    my $out1_pem = sprintf("pub_%s_out1.pem", $alg);
    my $out1_der = sprintf("pub_%s_out1.pem", $alg);

    # Check that the pkey app works with HSS public keys for DER and PEM
    ok(run(app(['openssl', 'pkey', '-pubin', '-inform', 'DER', '-in', $in_der,
                '-outform', 'DER', '-out', $out_der])));
    ok(!compare($in_der, $out_der), sprintf("pubkey DER/DER match: %s", $alg));

    ok(run(app(['openssl', 'pkey', '-pubin', '-inform', 'PEM', '-in', $in_pem,
                '-outform', 'PEM', '-out', $out_pem])));
    ok(!compare($in_pem, $out_pem), sprintf("pubkey PEM/PEM match: %s", $alg));

    ok(run(app(['openssl', 'pkey', '-pubin', '-inform', 'DER', '-in', $in_der,
                '-outform', 'PEM', '-out', $out1_pem])));
    ok(!compare($out1_pem, $in_pem), sprintf("pubkey DER/PEM match: %s", $alg));

    ok(run(app(['openssl', 'pkey', '-pubin', '-inform', 'PEM', '-in', $in_pem,
                '-outform', 'DER', '-out', $out1_der])));
    ok(!compare($out1_der, $in_der), sprintf("pubkey PEM/DER match: %s", $alg));

    # Check that the pkey app works with HSS public keys for TEXT
    my $expect_txt = data_file(sprintf("pub_%s.txt", $alg));
    my $out_txt = sprintf("pub_%s_out.text", $alg);
    ok(run(app(['openssl', 'pkey', '-pubin', '-inform', 'DER', '-in', $in_der,
                '-noout', '-text', '-out', $out_txt])));
    ok(!compare_text($expect_txt, $out_txt),
            sprintf("pubkey DER/text match: %s", $alg));
         
    # Check that pkeyutl supports HSS verify
    my $msg = data_file("msg.bin");
    my $sig = data_file(sprintf("sig_%s.bin", $alg));
    ok(run(app(['openssl', 'pkeyutl', '-pubin', '-inkey', $in_der,
                '-in', $msg, '-sigfile', $sig, '-verify'])));
    ok(!run(app(['openssl', 'pkeyutl', '-pubin', '-inkey', $in_der,
                 '-in', $msg, '-sigfile', $in_der, '-verify'])));
}
