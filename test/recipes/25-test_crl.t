#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_crl");

plan tests => 3;

require_ok(srctop_file('test','recipes','tconversion.pl'));

subtest 'crl conversions' => sub {
    tconversion("crl", srctop_file("test","testcrl.pem"));
};

ok(run(test(['crltest'])));
