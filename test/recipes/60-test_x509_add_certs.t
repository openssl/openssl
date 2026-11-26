#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License"). You may not use
# this file except in compliance with the License. You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_x509_add_certs");

plan tests => 1;

ok(run(test(["x509_add_certs_test",
             srctop_file("test", "certs", "ee-cert.pem"),
             srctop_file("test", "certs", "ca-cert.pem"),
             srctop_file("test", "certs", "root-cert.pem"),
             srctop_file("test", "certs",
                         "bad-cert-smtputf8-name-constraints.pem")])));
