#! /usr/bin/env perl
# Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file srctop_dir bldtop_file bldtop_dir/;

BEGIN {
setup("test_sslprovider");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');
use platform;

plan skip_all => "No TLS/SSL protocols are supported by this OpenSSL build"
    if alldisabled(grep { $_ ne "ssl3" } available_protocols("tls"));

plan tests => 3;

$ENV{OPENSSL_MODULES} = bldtop_dir("providers");
$ENV{OPENSSL_CONF_INCLUDE} = bldtop_dir("providers");

SKIP: {
    skip "Skipping FIPS installation", 1
        if disabled("fips");

    ok(run(perltest(['fipsinstall.pl', bldtop_dir()])),
       "fipsinstall");
}

ok(run(test(["sslprovidertest", srctop_dir("test", "certs"), "default",
             srctop_file("test", "default.cnf")])),
             "running sslprovidertest");

SKIP: {
    skip "Skipping FIPS provider test", 1
        if disabled("fips");

    ok(run(test(["sslprovidertest", srctop_dir("test", "certs"), "fips",
                 srctop_file("test", "fips.cnf")])),
                 "running sslprovidertest");
}
