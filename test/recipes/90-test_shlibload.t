#! /usr/bin/env perl
# Copyright 2016-2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test qw/:DEFAULT srctop_dir bldtop_dir/;
use OpenSSL::Test::Utils;

#Load configdata.pm

BEGIN {
    setup("test_shlibload");
}
use lib srctop_dir('Configurations');
use lib bldtop_dir('.');
use platform;

plan skip_all => "Test only supported in a shared build" if disabled("shared");
plan skip_all => "Test is disabled on AIX" if config('target') =~ m|^aix|;
plan skip_all => "Test is disabled on NonStop" if config('target') =~ m|^nonstop|;
plan skip_all => "Test only supported in a dso build" if disabled("dso");
plan skip_all => "Test is disabled in an address sanitizer build" unless disabled("asan");

plan tests => 4;

my $libcrypto = platform->sharedlib('libcrypto');
my $libssl = platform->sharedlib('libssl');

ok(run(test(["shlibloadtest", "-crypto_first", $libcrypto, $libssl])),
   "running shlibloadtest -crypto_first");

ok(run(test(["shlibloadtest", "-ssl_first", $libcrypto, $libssl])),
   "running shlibloadtest -ssl_first");

ok(run(test(["shlibloadtest", "-just_crypto", $libcrypto, $libssl])),
   "running shlibloadtest -just_crypto");

ok(run(test(["shlibloadtest", "-dso_ref", $libcrypto, $libssl])),
   "running shlibloadtest -dso_ref");
