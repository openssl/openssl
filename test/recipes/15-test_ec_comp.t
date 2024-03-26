#! /usr/bin/env perl
# Copyright 2015-2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT data_dir/;
use OpenSSL::Test::Utils;

setup("test_ec_comp");

# Only need to test a few curves as behaviour should be the same.
# Testing all the curves would take excessive time.
my @curvesdata = run(app(["openssl", "ecparam", "-list_curves"]), capture => 1);
my @curves;
foreach (@curvesdata) {
    my @parts = split(/:/, $_, 2);
    my $p = $parts[0];
    if ($p =~ /^\t/) { next; }
    $p =~ s/\s+//g;
    if (!($p =~ /(secp256k1|prime256v1|sect571r1|brainpoolP384r1)/)) { next; }
    push @curves, $p;
}

plan tests => 1 + scalar @curves;

ok(run(test(["ec_comp_test", data_dir("")])), "running ec_comp_test");

my @param_encs = qw/named_curve explicit/;
my @param_encs_e = qw/named_curve explicit unspecified/;
my @conv_forms = qw/uncompressed compressed hybrid/;
my @conv_forms_e = qw/uncompressed compressed hybrid unspecified/;
my $data_path = data_dir("");

sub classify_key {
    my $fn = shift;
    my @text = run(app(["openssl", "ec", "-in", $fn, "-text"]),
                   capture => 1);
    my $text = join "", @text;
    my @asn1 = run(app(["openssl", "asn1parse", "-dump", "-in", $fn]),
                   capture => 1);
    my $asn1 = join "", @asn1;

    $asn1 =~ s/.*BIT STRING//s;

    my $res_comp_type;
    if (grep /\s0000 - 00 0[67]/, $asn1) {
        $res_comp_type = "hybrid";
    } elsif (grep /\s0000 - 00 0[45]/, $asn1) {
        $res_comp_type = "uncompressed";
    } elsif (grep /\s0000 - 00 0[23]/, $asn1) {
        $res_comp_type = "compressed";
    } else {
        die "unknown compression type";
    }

    my $res_param_enc;
    if (grep /\sASN1 OID:/, $text) {
        $res_param_enc = "named_curve";
    } elsif (grep /\sField Type:/, $text) {
        $res_param_enc = "explicit";
    } else {
        die "unknown param form";
    }

    return "$res_comp_type/$res_param_enc";
}

SKIP: {
    skip "FIXME: Intentionally skipping CLI round-trip tests", scalar @curves;
    skip "EC is not supported by this OpenSSL build", scalar @curves if disabled("ec");

    foreach my $curve (@curves) {
        subtest "=== openssl ec CLI round-trip for curve $curve" => sub {
            foreach my $param_enc (@param_encs) {
                foreach my $conv_form (@conv_forms) {
                    # Run openssl ecparam -genkey using input parameters.
                    run(app(["openssl", "ecparam", "-check",
                             "-in", "$data_path/$curve-$param_enc.param",
                             "-conv_form", $conv_form, "-param_enc", $param_enc,
                             "-genkey", "-noout", "-out", "key.tmp"]));
                    my $expect = "$conv_form/$param_enc";
                    my $result = classify_key("key.tmp");
                    ok($expect eq $result, "(1): got '$result' expected '$expect'");

                    foreach my $param_enc2 (@param_encs_e) {
                        foreach my $conv_form2 (@conv_forms_e) {
                            # Now try round-tripping a key through openssl ec,
                            # potentially specifying new compression/param formats.
                            my @args = qw(openssl ec -in key.tmp -out key2.tmp);
                            if ($conv_form2 ne "unspecified") {
                                push(@args, "-conv_form");
                                push(@args, $conv_form2);
                            }
                            if ($param_enc2 ne "unspecified") {
                                push(@args, "-param_enc");
                                push(@args, $param_enc2);
                            }
                            run(app([@args]));

                            my $expect_conv = $conv_form2;
                            if ($expect_conv eq "unspecified") {
                                $expect_conv = $conv_form;
                            }

                            my $expect_param = $param_enc2;
                            if ($expect_param eq "unspecified") {
                                $expect_param = $param_enc;
                            }

                            my $expect2 = "$expect_conv/$expect_param";
                            my $result2 = classify_key("key2.tmp");
                            ok($expect2 eq $result2,
                               "(2): expected '$expect2' got '$result2'");
                        }
                    }
                }
            }
        }
    }
}
