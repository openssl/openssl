#! /usr/bin/env perl
# Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT data_file srctop_file/;

setup("test_external_krb5");

plan tests => 1;

SKIP: {
    skip "No external tests in this configuration", 1
        if disabled("external-tests");
    skip "krb5 not available", 1
        if ! -f srctop_file("krb5", "README");

    ok(run(cmd([data_file("krb5.sh")])), "running krb5 tests");
}
