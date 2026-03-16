#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test qw/:DEFAULT srctop_dir srctop_file result_dir/;
use OpenSSL::Test::Utils;
use File::Temp qw(tempfile);
use File::Path 2.00 qw(rmtree mkpath);

setup("test_memfail");

#
# Don't run this test if allocfail-tests isn't enabled, it won't work
#
plan skip_all => "$test_name requires allocfail-tests to be enabled"
    if disabled("allocfail-tests");

#
# We need to know how many mallocs we plan to fail, so run the test in count mode
# To tell us how many mallocs it executes
# We capture the result of the test into countinfo.txt
# and parse that to figure out what our values are
#
my $resultdir = result_dir();
run(test(["handshake-memfail", "count", srctop_dir("test", "certs")], stderr => "$resultdir/hscountinfo.txt"));

run(test(["x509-memfail", "count", srctop_file("test", "certs", "servercert.pem")], stderr => "$resultdir/x509countinfo.txt"));

run(test(["load_key_certs_crls_memfail", "count", srctop_file("test", "certs", "servercert.pem")], stderr => "$resultdir/load_key_certs_crls_countinfo.txt"));

sub get_count_info {
    my ($infile) = @_;
    my ($skipcount, $malloccount) = (0, 0);

    open my $handle, '<', "$infile" or return (0, 0);
    chomp(my @lines = <$handle>);
    close $handle;

    # Match the test program output: "skip: <number> count <number>"
    # Stderr may be captured with a "# " prefix per line (TAP-style).
    foreach (@lines) {
        if (/\bskip:\s*(\d+)\s+count\s+(\d+)/) {
            $skipcount = $1;
            $malloccount = $2;
            last;
        }
    }
    return ($skipcount, $malloccount);
}

my ($hsskipcount, $hsmalloccount) = get_count_info("$resultdir/hscountinfo.txt");

my ($x509skipcount, $x509malloccount) = get_count_info("$resultdir/x509countinfo.txt");

my ($load_key_certs_crls_skipcount, $load_key_certs_crls_malloccount) = get_count_info("$resultdir/load_key_certs_crls_countinfo.txt");

my $total_malloccount = $hsmalloccount + $x509malloccount + $load_key_certs_crls_malloccount;
plan skip_all => "could not get malloc counts (one or more count runs failed or output format changed)"
    if $total_malloccount == 0;

#
# Now we can plan our tests.  We plan to run malloccount iterations of this
# test
#
plan tests => $total_malloccount;

sub run_memfail_test {
    my $skipcount = $_[0];
    my @mallocseq = (1..$_[1]);
    my @cmd = $_[2];

    for my $idx (@mallocseq) {
        #
        # We need to setup our openssl malloc failures env var to fail the target malloc
        # the format of this string is a series of A@B;C@D tuples where A,C are the number
        # of mallocs to consider, and B,D are the likelihood that they should fail.
        # We always skip the first "skip" allocations, then iteratively guarantee that
        # next <idx> mallocs pass, followed by the next single malloc failing, with the remainder
        # passing
        #
        $ENV{OPENSSL_MALLOC_FAILURES} = "$skipcount\@0;$idx\@0;1\@100;0\@0";
        ok(run(test(@cmd)));
    }
}

run_memfail_test($hsskipcount, $hsmalloccount, ["handshake-memfail", "run", srctop_dir("test", "certs")]);

run_memfail_test($x509skipcount, $x509malloccount, ["x509-memfail", "run", srctop_file("test", "certs", "servercert.pem")]);

run_memfail_test($load_key_certs_crls_skipcount, $load_key_certs_crls_malloccount, ["load_key_certs_crls_memfail", "run", srctop_file("test", "certs", "servercert.pem")]);

