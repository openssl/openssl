#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT/;
use OpenSSL::Test::Utils;

setup("test_provider_child_teardown");

# Each scenario frees a parent library context and needs its own process.
my @modes = qw(orig keep-rand hmac-unload hmac-keep pkeyctx-unload
               keyname-unload cross cross-swap);

plan tests => scalar @modes;

foreach my $mode (@modes) {
    ok(run(test(["provider_child_teardown_test", $mode])),
       "child library context owner teardown: $mode");
}
