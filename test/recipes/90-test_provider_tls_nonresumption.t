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
use OpenSSL::Test::Utils;

setup("test_provider_tls_nonresumption");

plan skip_all => "TLS 1.3 is not supported by this build"
    if disabled("tls1_3");
plan skip_all => "no TLS 1.3 key exchange is available"
    if disabled("ec") && disabled("dh");

plan tests => 1;

ok(run(test(["provider_tls_nonresumption_test",
             srctop_file("apps", "server.pem"),
             srctop_file("apps", "server.pem")])),
   "provider TLS ciphersuites cannot create resumable sessions");
