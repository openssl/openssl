#! /usr/bin/env perl
# Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_x509_is_equal");

plan tests => 4;

# x509 match
ok(run(test(["x509_is_equal_test",
             "cert",
             srctop_file("test", "certs", "leaf.pem"),
             srctop_file("test", "certs", "leaf.pem"), "ok"])));
# x509 not match
ok(run(test(["x509_is_equal_test",
             "cert",
             srctop_file("test", "certs", "leaf.pem"),
             srctop_file("test", "certs", "interCA.pem"), "failed"])));
# x509 crl match
ok(run(test(["x509_is_equal_test",
             "crl",
             srctop_file("test", "certs", "test.crl"),
             srctop_file("test", "certs", "test.crl"), "ok"])));
# x509 crl not match
ok(run(test(["x509_is_equal_test",
             "crl",
             srctop_file("test", "certs", "test.crl"),
             srctop_file("test", "certs", "test2.crl"), "failed"])));
