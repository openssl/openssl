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
# Don't run this test if mdebug isn't enabled, it won't work
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

#
# Read the handshake result file into an array
#
open my $hshandle, '<', "$resultdir/hscountinfo.txt";
chomp(my @hslines = <$hshandle>);
close $hshandle;

#
# some line contains our counts, find and split that into an array
#
my @hsvals;
foreach(@hslines) {
    if ($_ =~/skip:/) {
        @hsvals = split ' ', $_;
        break;
    }
}

#
# The number of mallocs we need to skip is in entry two
# The number of mallocs to test is in entry 4
#
my $hsskipcount = $hsvals[2];
my $hsmalloccount = $hsvals[4];

#
# Read the x509 result file into an array
#
open my $x509handle, '<', "$resultdir/x509countinfo.txt";
chomp(my @x509lines = <$x509handle>);
close $x509handle;

#
# some line contains our counts, find and split that into an array
#
my @x509vals;
foreach(@x509lines) {
    if ($_ =~/skip:/) {
        @x509vals = split ' ', $_;
        break;
    }
}

#
# The number of mallocs we need to skip is in entry two
# The number of mallocs to test is in entry 4
#
my $x509skipcount = $x509vals[2];
my $x509malloccount = $x509vals[4];

#
# Now we can plan our tests.  We plan to run malloccount iterations of this
# test
#
plan tests => $hsmalloccount + $x509malloccount;

my @hsseq = (1..$hsmalloccount);
for my $idx (@hsseq) {
    #
    # We need to setup our openssl malloc failures env var to fail the target malloc
    # the format of this string is a series of A@B;C@D tuples where A,C are the number
    # of mallocs to consider, and B,D are the likelyhood that they should fail.
    # We always skip the first "skip" allocations, then iteratively guarantee that
    # next <idx> mallocs pass, followed by the next single malloc failing, with the remainder
    # passing
    #
    $ENV{OPENSSL_MALLOC_FAILURES} = "$hsskipcount\@0;$idx\@0;1\@100;0\@0"; 
    ok(run(test(["handshake-memfail", "run", srctop_dir("test", "certs")])));
}

my @x509seq = (1..$x509malloccount);
for my $idx (@x509seq) {
    #
    # We need to setup our openssl malloc failures env var to fail the target malloc
    # the format of this string is a series of A@B;C@D tuples where A,C are the number
    # of mallocs to consider, and B,D are the likelyhood that they should fail.
    # We always skip the first "skip" allocations, then iteratively guarantee that
    # next <idx> mallocs pass, followed by the next single malloc failing, with the remainder
    # passing
    #
    $ENV{OPENSSL_MALLOC_FAILURES} = "$x509skipcount\@0;$idx\@0;1\@100;0\@0";
    ok(run(test(["x509-memfail", "run", srctop_file("test", "certs", "servercert.pem")])));
}

