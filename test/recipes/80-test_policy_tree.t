#! /usr/bin/env perl
# Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use POSIX;
use OpenSSL::Test qw/:DEFAULT srctop_file with data_file/;

use OpenSSL::Test::Utils;
use OpenSSL::Glob;

setup("test_policy_tree");

plan skip_all => "No EC support" if disabled("ec");

plan tests => 6;

# The small pathological tree is expected to work
my $small_chain = srctop_file("test", "recipes", "80-test_policy_tree_data",
                              "small_policy_tree.pem");
my $small_leaf = srctop_file("test", "recipes", "80-test_policy_tree_data",
                             "small_leaf.pem");

ok(run(app(["openssl", "verify", "-CAfile", $small_chain,
            "-policy_check", $small_leaf])),
   "test small policy tree");

# The large pathological tree is expected to fail
my $large_chain = srctop_file("test", "recipes", "80-test_policy_tree_data",
                              "large_policy_tree.pem");
my $large_leaf = srctop_file("test", "recipes", "80-test_policy_tree_data",
                             "large_leaf.pem");

ok(!run(app(["openssl", "verify", "-CAfile", $large_chain,
             "-policy_check", $large_leaf])),
   "test large policy tree");

# Test for issue #26099 - Certificate policy validation
# API test verifying NULL policyid rejection
ok(run(test(["bad_policy_test",
             srctop_file("test", "certs", "ee-cert-policies.pem")])),
   "test NULL policyid rejection (issue #26099)");

# CLI test - verify openssl can parse certificates with valid policies
ok(run(app(["openssl", "x509",
            "-in", srctop_file("test", "certs", "ee-cert-policies.pem"),
            "-text", "-noout"])),
   "test parsing certificate with valid policies");

# CLI test - verify policy validation works correctly with valid policies
# This exercises the policy validation code path with openssl verify -policy_check
# to ensure the fix doesn't break normal policy processing
my $ca_pol_cert = srctop_file("test", "certs", "ca-pol-cert.pem");
my $ee_pol_cert = srctop_file("test", "certs", "ee-cert-policies.pem");

ok(run(app(["openssl", "verify",
            "-no_check_time",
            "-partial_chain",
            "-CAfile", $ca_pol_cert,
            "-policy_check",
            $ee_pol_cert])),
   "test policy validation with verify command (issue #26099)");

# CLI test - verify OpenSSL rejects certificates with invalid policies
# This tests a certificate with duplicate policy OIDs, which is also invalid per RFC 5280
# and should be rejected by the same code path that rejects NULL policyid
my $bad_pol_cert = srctop_file("test", "certs", "ee-cert-policies-bad.pem");

# Verification should fail for certificate with invalid policy extension
ok(!run(app(["openssl", "verify",
             "-no_check_time",
             "-partial_chain",
             "-CAfile", $ca_pol_cert,
             "-policy_check",
             $bad_pol_cert])),
   "CLI test verifying OpenSSL rejects certificate with invalid policies (issue #26099)");
