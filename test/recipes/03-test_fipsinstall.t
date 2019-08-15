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

plan tests => 2;

my $infile = srctop_file("providers", "fips.so");
$ENV{'OPENSSL_MODULES'} = srctop_file("providers");

# output a fips.conf file containing mac data
ok(run(app(['openssl', 'fipsinstall', '-out', 'fips.conf', '-module', $infile,
            '-provider_name', 'fips', '-mac_name', 'HMAC',
            '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
            '-section_name', 'fips_install'])),
   "fipinstall");

# Verify the fips.conf file
ok(run(app(['openssl', 'fipsinstall', '-in', 'fips.conf', '-module', $infile,
            '-provider_name', 'fips', '-mac_name', 'HMAC',
            '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
            '-section_name', 'fips_install', '-verify'])),
   "fipinstall verify");
