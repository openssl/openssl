#! /usr/bin/env perl
# Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use File::Copy;
use OpenSSL::Glob;
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_fipsinstall");

plan skip_all => "Test disabled in this configuration"
    if $^O eq 'MSWin32';

plan tests => 4;

my $infile = srctop_file("test", "p_test.so");
$ENV{'OPENSSL_MODULES'} = srctop_file("test");
ok(!run(app([qw{openssl fipsinstall -in unknown -cfg fips.conf -mac HMAC -macopt digest:SHA224 -macopt hexkey:00}])), "unknown infile");
ok(!run(app(['openssl', 'fipsinstall', '-in', $infile, '-mac', 'HMAC', '-macopt', 'digest:SHA224', '-macopt', 'hexkey:00'])), "no config file");
ok(run(app(['openssl', 'fipsinstall', '-in', $infile, '-cfg', 'fips.conf', '-mac', 'HMAC', '-macopt', 'digest:SHA224', '-macopt', 'hexkey:00', '-section', 'test'])), "fipinstall");
ok(run(app(['openssl', 'fipsinstall', '-in', $infile, '-cfg', 'fips.conf', '-mac', 'HMAC', '-macopt', 'digest:SHA224', '-macopt', 'hexkey:00', '-section', 'test', '-verify'])), "fipsinstall -verify");