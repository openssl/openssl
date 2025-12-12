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

setup("test_lms_codecs");

# The test vectors were generated using modified Bouncy Castle tests
# from core/src/test/java/org/bouncycastle/pqc/crypto/test/LMSTest.java
my @algs = qw(sha256_n24_w1 shake_n24_w1 shake_n24_w2 shake_n24_w4 shake_n24_w8 shake_n32_w1 shake_n32_w8);

plan skip_all => "LMS isn't supported in this build"
    if disabled("lms");

plan tests => @algs * 7;

foreach my $alg (@algs) {
    my $pubpem =data_file(sprintf("%s_pub.pem", $alg));
    my $pubder = data_file(sprintf("%s_pub.der", $alg));
    my $pubtxt = data_file(sprintf("%s_pub.txt", $alg));
    my $msg = data_file(sprintf("%s_msg.bin", $alg));
    my $sig = data_file(sprintf("%s_sig.bin", $alg));
    my $outpubder = sprintf("%s_pubout.der", $alg);
    my $outpubpem = sprintf("%s_pubout.pem", $alg);
    my $outpubtxt = sprintf("%s_pubout.txt", $alg);
    
    # Load Public PEM and generate Public DER
    ok(run(app([qw(openssl pkey -pubin -outform DER -in),
                $pubpem, '-out', $outpubder])));
    ok(!compare($pubder, $outpubder),
            sprintf("pubkey DER match: %s", $alg));

    # Load Public DER and generate Public PEM
    ok(run(app([qw(openssl pkey -pubin -inform DER -outform PEM -in),
                $pubder, '-out', $outpubpem])));
    ok(!compare($pubpem, $outpubpem),
            sprintf("pubkey PEM match: %s", $alg));

    # Check text encoding
    ok(run(app([qw(openssl pkey -pubin -noout -text -in),
                $pubpem, '-out', $outpubtxt])));
    ok(!compare_text($pubtxt, $outpubtxt),
            sprintf("pubkey TEXT match: %s", $alg));

    # Perform verify
    ok(run(app([qw(openssl pkeyutl -verify -rawin -pubin -inkey),
                $pubpem, '-in', $msg, '-sigfile', $sig])));
}
