#! /usr/bin/env perl
# Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test;
use OpenSSL::Test::Utils;

setup("test_accept_dtls");

plan skip_all => "DTLSv1 is not supported by this OpenSSL build"
    if disabled("dtls1");

plan tests => 1;

ok(run(test(["dtlsv1accepttest", srctop_file("apps", "server.pem"),
             srctop_file("apps", "server.pem")])), "running dtlsv1accepttest");
