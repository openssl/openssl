#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test qw/:DEFAULT result_file/;
use OpenSSL::Test::Utils;

setup("test_cleanse");

plan tests => 1;

my $report = result_file("cleansetest.err");

# The program performs an out-of-bounds OPENSSL_cleanse() and dies with a
# report on any build whose ASan instrumentation covers the cleanse, so
# this test FAILS exactly on the CI jobs that cover the instrumentation.
ok(run(test(["cleansetest"], stderr => $report)),
   "out-of-bounds OPENSSL_cleanse not covered by sanitizer instrumentation");

# Surface the captured ASan report as TAP diagnostics
if (open(my $fh, "<", $report)) {
    while (my $line = <$fh>) {
        chomp $line;
        diag($line);
    }
    close $fh;
}
