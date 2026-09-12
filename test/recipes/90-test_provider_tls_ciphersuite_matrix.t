#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License"). You may not use
# this file except in compliance with the License. You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT bldtop_dir data_file srctop_dir srctop_file/;
use OpenSSL::Test::Utils;

setup("test_provider_tls_ciphersuite_matrix");

plan skip_all => "module support is disabled" if disabled("module");
plan skip_all => "TLS 1.3 is disabled" if disabled("tls1_3");
plan skip_all => "no TLS 1.3 key exchange is available"
    if disabled("ec") && disabled("dh");

my $input = srctop_file("test", "recipes",
    "90-test_provider_tls_ciphersuite_data", "handshake.cnf.in");
my $provider_conf = srctop_file("test", "recipes",
    "90-test_provider_tls_ciphersuite_data", "provider.cnf");
my $output = "provider-ciphersuite-handshake.cnf";

$ENV{OPENSSL_MODULES} = bldtop_dir("test");
$ENV{TEST_CERTS_DIR} = srctop_dir("test", "certs");

plan tests => 2;

ok(run(perltest(["generate_ssl_tests.pl", $input, "tls-provider"],
       interpreter_args => ["-I", srctop_dir("util", "perl")],
       stdout => $output)), "generate provider ciphersuite matrix");
ok(run(test(["ssl_test", $output, "tls-provider", $provider_conf])),
   "run provider ciphersuite matrix through ssl_test");
