#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT bldtop_file data_file srctop_file cmdstr/;

setup("test_external_cryptofuzz");

plan skip_all => "No external tests in this configuration"
    if disabled("external-tests");
plan skip_all => "Cryptofuzz not available"
    if ! -f srctop_file("cryptofuzz", "README.md");
plan skip_all => "Cryptofuzz only available in a static build"
    if disabled("static");

plan tests => 1;

ok(run(cmd(["sh", data_file("cryptofuzz.sh")])), "running Cryptofuzz tests");
