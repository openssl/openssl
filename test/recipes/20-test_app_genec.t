#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

# The genpkey command line surface for EC: the -pkeyopt names, the output
# format and text options, and the negative cases.  None of this varies
# from one curve to the next, so only a few representative curves are
# used here.  Every curve is covered in this process by genec_test, which
# is driven by test/recipes/15-test_genec.t.

sub supported_pass {
    my $str = shift;

    ok(run(@_), $str);
}

sub supported_fail {
    my $str = shift;

    ok(!run(@_), $str);
}

setup("test_app_genec");

plan skip_all => "This test is unsupported in a no-ec build"
    if disabled("ec");

my @curve_list = ('prime256v1');
push(@curve_list, 'sect233k1')
    if !disabled("ec2m");
push(@curve_list, 'P-256');
push(@curve_list, 'SM2')
    if !disabled("sm2");

my @explicit_only_curves = ();
push(@explicit_only_curves, qw(
        Oakley-EC2N-3
        Oakley-EC2N-4
    )) if !disabled("ec2m");

my @param_encodings = ('named_curve', 'explicit');

my @output_formats = ('PEM', 'DER');

plan tests => scalar(@curve_list) * scalar(@param_encodings)
    * (1 + scalar(@output_formats)) # Try listed @output_formats and text output
    * 2                             # Test generating parameters and keys
    + 1                             # Checking that with no curve it fails
    + 1                             # Checking that with unknown curve it fails
    + 1                             # Checking that a bad encoding fails
    + 1                             # Subtest for explicit only curves
    + 1                             # base serializer test
    ;

ok(!run(app([ 'openssl', 'genpkey',
              '-algorithm', 'EC'])),
   "genpkey EC with no params should fail");

ok(!run(app([ 'openssl', 'genpkey',
              '-algorithm', 'EC',
              '-pkeyopt', 'ec_paramgen_curve:bogus_foobar_curve'])),
   "genpkey EC with unknown curve name should fail");

ok(!run(app([ 'openssl', 'genpkey',
              '-algorithm', 'EC',
              '-pkeyopt', 'ec_paramgen_curve:prime256v1',
              '-pkeyopt', 'ec_param_enc:bogus_foobar_encoding'])),
   "genpkey EC with unknown parameter encoding should fail");

ok(run(app([ 'openssl', 'genpkey',
             '-provider-path', 'providers',
             '-provider', 'base',
             '-config', srctop_file("test", "default.cnf"),
             '-algorithm', 'EC',
             '-pkeyopt', 'ec_paramgen_curve:prime256v1',
             '-text'])),
    "generate a private key and serialize it using the base provider");

foreach my $curvename (@curve_list) {
    foreach my $paramenc (@param_encodings) {

        # --- Test generating parameters ---

        supported_pass("genpkey EC params ${curvename} with ec_param_enc:'${paramenc}' (text)",
              app([ 'openssl', 'genpkey', '-genparam',
                    '-algorithm', 'EC',
                    '-pkeyopt', 'ec_paramgen_curve:'.$curvename,
                    '-pkeyopt', 'ec_param_enc:'.$paramenc,
                    '-text']));

        foreach my $outform (@output_formats) {
            my $outfile = "ecgen.${curvename}.${paramenc}." . lc $outform;
            supported_pass("genpkey EC params ${curvename} with ec_param_enc:'${paramenc}' (${outform})",
                  app([ 'openssl', 'genpkey', '-genparam',
                        '-algorithm', 'EC',
                        '-pkeyopt', 'ec_paramgen_curve:'.$curvename,
                        '-pkeyopt', 'ec_param_enc:'.$paramenc,
                        '-outform', $outform,
                        '-out', $outfile]));
        }

        # --- Test generating actual keys ---

        supported_pass("genpkey EC key on ${curvename} with ec_param_enc:'${paramenc}' (text)",
              app([ 'openssl', 'genpkey',
                    '-algorithm', 'EC',
                    '-pkeyopt', 'ec_paramgen_curve:'.$curvename,
                    '-pkeyopt', 'ec_param_enc:'.$paramenc,
                    '-text']));

        foreach my $outform (@output_formats) {
            my $outfile = "ecgen.${curvename}.${paramenc}." . lc $outform;
            my $outpubfile = "ecgen.${curvename}.${paramenc}-pub." . lc $outform;
            supported_pass("genpkey EC key on ${curvename} with ec_param_enc:'${paramenc}' (${outform})",
                  app([ 'openssl', 'genpkey',
                        '-algorithm', 'EC',
                        '-pkeyopt', 'ec_paramgen_curve:'.$curvename,
                        '-pkeyopt', 'ec_param_enc:'.$paramenc,
                        '-outform', $outform,
                        '-out', $outfile,
                        '-outpubkey', $outpubfile]));
        }
    }
}

subtest "test curves that only support explicit parameters encoding" => sub {
    plan skip_all => "This test is unsupported under current configuration"
            if scalar(@explicit_only_curves) <= 0;

    plan tests => scalar(@explicit_only_curves) * 2;

    foreach my $curvename (@explicit_only_curves) {
        supported_fail("genpkey EC params ${curvename} with ec_param_enc:'named_curve' should fail",
              app([ 'openssl', 'genpkey', '-genparam',
                    '-algorithm', 'EC',
                    '-pkeyopt', 'ec_paramgen_curve:'.$curvename,
                    '-pkeyopt', 'ec_param_enc:named_curve',
                    '-text']));

        supported_pass("genpkey EC params ${curvename} with ec_param_enc:'explicit'",
              app([ 'openssl', 'genpkey', '-genparam',
                    '-algorithm', 'EC',
                    '-pkeyopt', 'ec_paramgen_curve:'.$curvename,
                    '-pkeyopt', 'ec_param_enc:explicit',
                    '-text']));
    }
};
