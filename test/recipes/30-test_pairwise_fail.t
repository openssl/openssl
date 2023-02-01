#! /usr/bin/env perl
# Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT bldtop_dir srctop_file srctop_dir data_file);
use OpenSSL::Test::Utils;

BEGIN {
setup("test_pairwise_fail");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

plan skip_all => "These tests are unsupported in a non fips build"
    if disabled("fips");

plan tests => 5;

SKIP: {
    skip "Skip RSA test because of no rsa in this build", 1
        if disabled("rsa");
    ok(run(test(["pairwise_fail_test", "-config", srctop_file("test","fips.cnf"),
                 "-pairwise", "rsa"])),
       "fips provider rsa keygen pairwise failure test");
}

SKIP: {
    skip "Skip EC test because of no ec in this build", 2
        if disabled("ec");
    ok(run(test(["pairwise_fail_test", "-config", srctop_file("test","fips.cnf"),
                 "-pairwise", "ec"])),
       "fips provider ec keygen pairwise failure test");
    ok(run(test(["pairwise_fail_test", "-config", srctop_file("test","fips.cnf"),
                 "-pairwise", "eckat", "-FIPSVersion", ">=3.1.0"])),
       "fips provider ec keygen kat failure test");
}

SKIP: {
    skip "Skip DSA tests because of no dsa in this build", 3
        if disabled("dsa");
    ok(run(test(["pairwise_fail_test", "-config", srctop_file("test","fips.cnf"),
                 "-pairwise", "dsa", "-dsaparam", data_file("dsaparam.pem")])),
       "fips provider dsa keygen pairwise failure test");
    ok(run(test(["pairwise_fail_test", "-config", srctop_file("test","fips.cnf"),
                 "-pairwise", "dsakat", "-dsaparam", data_file("dsaparam.pem"),
                 "-FIPSVersion", ">=3.1.0"])),
       "fips provider dsa keygen kat failure test");
}
