#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT);
use OpenSSL::Test::Utils;

setup("test_err_string_init");

plan skip_all => "This test should not be run under valgrind"
    if defined $ENV{OSSL_USE_VALGRIND};

# Fail each of the first few allocations made by ERR_reason_error_string()
# when it initialises the error string table (thread local storage, lock,
# hash table, hash buckets), one per run.  The index of the allocation to
# fail is passed in the environment, as the scenario runs before the test
# framework is set up.  Then do the same with every allocation from that
# index onwards failing.
my @fail_at = (0 .. 7);

plan tests => 2 * scalar @fail_at;

local $ENV{OPENSSL_TEST_MFAIL_DISABLE} = 1;
local $ENV{ASAN_OPTIONS} = "allocator_may_return_null=true";
local $ENV{MSAN_OPTIONS} = "allocator_may_return_null=true";

foreach my $n (@fail_at) {
    local $ENV{ERR_STRING_INIT_FAIL_AT} = $n;
    ok(run(test(["err_string_init_test"])),
       "allocation failure $n during error string initialisation");
}

foreach my $n (@fail_at) {
    local $ENV{ERR_STRING_INIT_FAIL_AT} = $n;
    local $ENV{ERR_STRING_INIT_FAIL_PERSIST} = 1;
    ok(run(test(["err_string_init_test"])),
       "allocation failures from $n on during error string initialisation");
}
