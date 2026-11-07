#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;
use OpenSSL::Test;
use OpenSSL::Test::Utils;

setup("test_crypto_init");
plan skip_all => "Requires Linux pthreads and linker wrapping"
    unless config('target') =~ /^linux-/ && !disabled('threads');
plan tests => 72;

for my $failure (0, 1, 2, 'master') {
    for my $cleanup ('cleanup', 'deferred') {
        next if $failure eq 'master' && $cleanup eq 'deferred';
        ok(run(test(['crypto_tls_init_test', $failure, $cleanup])),
           "TLS key failure $failure with $cleanup cleanup");
    }
}
for my $operation ('lock', 'tls', 'registry', 'strings', 'strings-insert') {
    for my $point (0 .. 12) {
        ok(run(test(['crypto_bootstrap_test', $operation, $point])),
           "$operation allocation failure $point");
    }
}
