#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License"); you may not use
# this file except in compliance with the License. You may obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_dtls_listener_races");

plan skip_all => "test_dtls_listener_races needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "test_dtls_listener_races needs DTLS enabled"
    if disabled("dtls");

plan skip_all => "test_dtls_listener_races needs the threads feature enabled"
    if disabled("threads");

plan tests => 2;

my @credentials = (srctop_file("apps", "server.pem"),
                   srctop_file("apps", "server.pem"));

ok(run(test(["dtls_multithread_test", "-test",
             "test_dtls_listener_clear_race", @credentials])),
   "running in-place listener clear race test");

ok(run(test(["dtls_multithread_test", "-test",
             "test_dtls_listener_clear_replace_race", @credentials])),
   "running replacement listener clear race test");
