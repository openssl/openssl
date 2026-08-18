#! /usr/bin/env perl
# Copyright 2016-2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_dir bldtop_dir/;

BEGIN {
    setup("test_client_cache");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

plan skip_all => "TLS is disabled in this OpenSSL build" if disabled("tls1") && disabled("tls1_1") && disabled("tls1_2");

plan tests => 1;

ok(run(test(["client_cache_test", srctop_dir("test", "certs")])), "running client_cache_test");
