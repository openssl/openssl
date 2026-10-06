#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Tests for the constant-time validation helpers in constant_time.h:
# - CONSTTIME_SECRET
# - CONSTTIME_DECLASSIFY
# - constant_time_declassify_u32()
#
# Most of the modes below check whether Valgrind flags code that is
# deliberately NOT constant-time. The accompanying recipe asserts that the
# harness flags it. Each such mode is a separate process because Valgrind's
# verdict is delivered as a process exit code via Valgrind's --error-exitcode.
#
# The "identity" mode is different: It ensures constant_time_declassify_u32()
# still exists and functions correctly when used OUTSIDE enable-ct-validation.
# Thus this mode uses the ordinary test framework pass/fail signal
# and does not require Valgrind.

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT result_file);
use OpenSSL::Test::Utils;

setup("test_ct_validation_helpers");

my $NUM_VALGRIND_TESTS = 6;
my $NUM_ALWAYS_TESTS = 1;

plan tests => $NUM_VALGRIND_TESTS + $NUM_ALWAYS_TESTS;

SKIP: {
    # Ensure test binary is wrapped in Valgrind
    skip "This test requires a build with enable-ct-validation", $NUM_VALGRIND_TESTS
        if disabled("ct-validation");
    skip "This test requires the test suite to be run with OSSL_VALGRIND_CT=yes", $NUM_VALGRIND_TESTS
        unless defined $ENV{OSSL_VALGRIND_CT};

    # Run one mode of ct_validation_helpers_test, capturing Valgrind's report
    # (which it writes to stderr). Returns the run's success flag and report text.
    my $ct_run = sub {
        my ($mode) = @_;
        my $errfile = result_file("ct_validation_helpers_$mode.txt");
        my $ok = run(test(["ct_validation_helpers_test", $mode], stderr => $errfile));
        my $report = "";

        if (open(my $fh, '<', $errfile)) {
            local $/ = undef;
            $report = <$fh>;
            close($fh);
        }
        return ($ok, $report);
    };

    my ($ok, $report);

    # "branch" mode: Ensure Valgrind flags a branch (a loop iteration count) on a
    # secret marked with CONSTTIME_SECRET.
    #
    # Valgrind should report:
    # "Conditional jump or move depends on uninitialised value(s)".
    ($ok, $report) = $ct_run->("branch");
    ok(!$ok, "secret-dependent branch is rejected");
    like($report, qr/uninitiali[sz]ed/i,
         "secret-dependent branch is reported as an uninitialised-value error");

    # "index" mode: Ensure Valgrind flags a lookup table index derived from a
    # secret marked with CONSTTIME_SECRET.
    #
    # Valgrind should report:
    # "Use of uninitialised value".
    ($ok, $report) = $ct_run->("index");
    ok(!$ok, "secret-dependent table index is rejected");
    like($report, qr/uninitiali[sz]ed/i,
         "secret-dependent table index is reported as an uninitialised-value error");

    # "control" mode: Ensure Valgrind does NOT flag a branch on a secret that has
    # been declassified by CONSTTIME_DECLASSIFY.
    ($ok, $report) = $ct_run->("control");
    ok($ok, "constant-time code with a declassified output is accepted");

    # "mask" mode: Ensure Valgrind does NOT flag a branch on the result of
    # constant_time_declassify_u32().
    #
    # Uses the same calling pattern as constant_time_declassify_u32's current
    # unique caller:
    # - A constant_time_ge()/constant_time_lt() mask (0 or all-ones) computed from
    #   secret data is declassified and immediately branched on. The boolean
    #   outcome of a rejection-sampling check is safe to leak even though the data
    #   behind it is not.
    ($ok, $report) = $ct_run->("mask");
    ok($ok, "a declassified comparison mask can be branched on");
}

# "identity" mode: Ensure constant_time_declassify_u32() returns its input
# unmodified, independent of whether Valgrind or enable-ct-validation are
# enabled.
ok(run(test(["ct_validation_helpers_test", "identity"])),
   "constant_time_declassify_u32() is an identity function");
