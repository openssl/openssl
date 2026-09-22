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
# framework is set up.
my @fail_at = (0 .. 7);

plan tests => scalar @fail_at;

local $ENV{OPENSSL_TEST_MFAIL_DISABLE} = 1;

# Leak checking is turned off for this test.
#
# Failing an allocation made while the thread local storage of this thread is
# being created leaves the error state that is created in order to report that
# very failure unreachable:  CRYPTO_THREAD_set_local_ex() reports the failed
# allocation of its own sparse array, reporting enters ossl_err_get_state_int(),
# which creates both the sparse array and an ERR_STATE, and the outer call then
# overwrites the slot again.  That is a pre-existing re-entrancy problem in the
# allocation failure reporting path, independent of the error string
# initialisation fixed here, so this test does not try to assert anything about
# it.
local $ENV{ASAN_OPTIONS} = "allocator_may_return_null=true:detect_leaks=0";
local $ENV{MSAN_OPTIONS} = "allocator_may_return_null=true";

foreach my $n (@fail_at) {
    local $ENV{ERR_STRING_INIT_FAIL_AT} = $n;
    ok(run(test(["err_string_init_test"])),
       "allocation failure $n during error string initialisation");
}
