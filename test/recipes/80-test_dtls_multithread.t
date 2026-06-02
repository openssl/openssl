#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_dtls_multithread");

plan skip_all => "test_dtls_multithread needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "test_dtls_multithread needs DTLS enabled"
    if disabled("dtls");

plan skip_all => "test_dtls_multithread needs the threads feature enabled"
    if disabled("threads");

plan tests => 1;

ok(run(test(["dtls_multithread_test", srctop_file("apps", "server.pem"),
             srctop_file("apps", "server.pem")])), "running dtls_multithread_test");