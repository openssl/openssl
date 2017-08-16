#!/usr/bin/env perl
# Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Glob;
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_fuzz");

my @fuzzers = ('server');
plan tests => scalar @fuzzers;

foreach my $f (@fuzzers) {
    subtest "Fuzzing $f" => sub {
        my @files = glob(srctop_file('fuzz', 'corpora', $f, '*'));
        push @files, glob(srctop_file('fuzz', 'corpora', "$f-*", '*'));

        plan skip_all => "No corpora for $f-test" unless @files;

        plan tests => scalar @files + 1;

        foreach (@files) {
            ok(run(fuzz(["$f-test", $_])));
        }
        ok(run(fuzz(["$f-test"])));
    }
}
