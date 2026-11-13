#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT srctop_file srctop_dir bldtop_dir/;

BEGIN {
    setup("test_cmp_http_invalid_options");
}
use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

require(srctop_file("test", "recipes", "cmp_http.pl"));

cmp_http_tests("invalid_options");
