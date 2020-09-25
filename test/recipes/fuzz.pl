# Copyright 2016-2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Glob;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

sub fuzz_tests {
    my @fuzzers = @_;

    foreach my $f (@fuzzers) {
        subtest "Fuzzing $f" => sub {
            my @dir = glob(srctop_file('fuzz', 'corpora', "$f"));

            plan skip_all => "No directory fuzz/corpora/$f" unless @dir;
            plan tests => scalar @dir; # likely 1

            foreach (@dir) {
                ok(run(fuzz(["$f-test", $_])));
            }
        }
    }
}

1;
