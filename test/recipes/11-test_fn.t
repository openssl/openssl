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
setup("test_fn");

my @files = qw( bnmul.txt bnshift.txt bnsum.txt bnmod.txt );

plan tests => scalar(@files);

foreach my $f (@files) {
    ok(run(test(["fntest", srctop_file("test", "recipes", "10-test_bn_data", $f)])),
       "running fntest $f");
}
