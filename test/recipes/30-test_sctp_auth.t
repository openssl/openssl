#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
# Licensed under the Apache License 2.0.

use strict;
use warnings;

use OpenSSL::Test;
use OpenSSL::Test::Utils;

setup("test_sctp_auth");

# Skip at harness level if the build disabled SCTP
plan skip_all => "SCTP is disabled in this build" if disabled("sctp");

# Windows does not provide the needed SCTP stack by default
plan skip_all => "SCTP test not supported on this platform"
    if $^O eq "MSWin32";

plan skip_all => "SCTP disabled"
    if disabled("sctp");

plan skip_all => "no SCTP kernel support detected"
    if $^O =~ /^(MSWin32|darwin)$/;  # keep simple; Linux/*BSD run it

plan tests => 1;

ok(run(test(["sctp_auth_test"])),
   "basic SCTP AUTH control paths on one-to-many socket");
