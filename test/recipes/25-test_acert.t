#! /usr/bin/env perl
# Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_acert");

plan tests => 6;

my @certs = qw(test certs);
my $acert = srctop_file(@certs, "acert.pem");

ok(run(app(["openssl", "acert", "-in", $acert, "-text", "-out",
            srctop_file(@certs, "acert_out.pem")])), 'Read attr certificate');

my $holder = srctop_file(@certs, "ee-cert.pem");
my $issuer = srctop_file(@certs, "aa.pem");
my $issuerkey = srctop_file(@certs, "aa-key.pem");

my $outacert = "acertout.pem";

ok(run(app(["openssl", "acert", "-new", "-holder", $holder, "-AA", $issuer,
            "-AAkey", $issuerkey, "-out", $outacert])));

my $badstart = "850101124500Z";
my $start = "19850101124500Z";

ok(!run(app(["openssl", "acert", "-new",
             "-holder", $holder, "-AA", $issuer, "-AAkey", $issuerkey,
             "-out", $outacert, "-startdate", $badstart])),
   'Testing bad start date format (ASN1_UTCTIME)');

ok(run(app(["openssl", "acert", "-new",
            "-holder", $holder, "-AA", $issuer, "-AAkey", $issuerkey,
            "-out", $outacert, "-startdate", $start])),
   'Testing good start date format (ASN1_GENERALIZEDTIME)');

ok(run(app(["openssl", "acert", "-new",
            "-holder", $holder, "-AA", $issuer, "-AAkey", $issuerkey,
            "-out", "acert-pss.pem",
            "-sigopt", "rsa_padding_mode:pss"])),
   'Test signing options');

ok(run(app(["openssl", "acert", "-new", 
             "-holder", $holder, "-AA", $issuer, "-AAkey", $issuerkey,
             "-out", "acert-config-attr.pem",
             "-config", srctop_file('test', 'acert.cnf')])),
   'Load attributes from config file');

#is(cmp_text($out_msb, $msb),
#   0, 'Comparing esc_msb output with cyrillic.msb');
#is(cmp_text($out_msb, $msb),
#   0, 'Comparing esc_msb output with cyrillic.msb');
