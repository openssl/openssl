#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test::Simple;
use OpenSSL::Test qw/:DEFAULT srctop_file srctop_dir bldtop_dir/;
use OpenSSL::Test::Utils;

BEGIN {
setup("test_prov_config");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

plan tests => 1;

ok(run(test(["libctx_config_test", srctop_file("test", "tls-max-v11.cnf"),
                                 srctop_file("test", "tls-max-v12.cnf")])),
    "running libctx_config_test default.cnf");
