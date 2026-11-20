#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
# Copyright (c) 2018, Oracle and/or its affiliates.  All rights reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_evp_skey");

my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);

plan tests => $no_fips ? 1 : 2;

ok(run(test(["evp_skey_test", "-config", srctop_file("test", "default.cnf")])),
   "running evp_skey_test with default provider");

unless ($no_fips) {
    my $fips_conf = srctop_file("test", "fips-and-base.cnf");

    SKIP: {
        # SKEYMGMT support in FIPS provider requires >= 3.6.0
        run(test(["fips_version_test", "-config", $fips_conf, ">=4.2.0"]),
                 capture => 1, statusvar => \my $fips_ge_4_2);
        skip "FIPS provider version < 4.2.0 (SKEYMGMT not supported)", 1
            if !$fips_ge_4_2;

        ok(run(test(["evp_skey_test", "-config", $fips_conf])),
           "running evp_skey_test with FIPS provider");
    }
}
