#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT bldtop_file data_file srctop_file cmdstr/;

setup("test_external");

plan skip_all => "No external tests in this configuration"
    if disabled("external-tests");

plan tests => 1;

SKIP: {
    skip "PYCA Cryptography not available", 1
        if ! -f srctop_file("pyca-cryptography", "setup.py");
    skip "PYCA tests not available on Windows or VMS", 1
        if $^O =~ /^(VMS|MSWin32)$/;

    ok(run(cmd(["sh", data_file("cryptography.sh")])),
        "running Python Cryptography tests");
}

