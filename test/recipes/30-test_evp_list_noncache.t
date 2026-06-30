#! /usr/bin/env perl
# Copyright 2015-2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test qw/:DEFAULT srctop_file srctop_dir/;

setup("test_noncaching_evp_fetch");

plan tests => 1;

# This tells the p_ossltest provider to request no caching of algs
$ENV{OSSL_TEST_PROVIDER_NO_CACHE} = "yes";

my $provdir = srctop_dir("test");

# list all algorithms in p_ossltest, this exercises the EVP_*do_all_provided paths when algorithms
# are not being cached
#
ok(run(app(["openssl", "list", "-provider-path", $provdir, "-provider", "p_ossltest", "-all-algorithms"])),
            "list provided algs when provider requests no caching");


