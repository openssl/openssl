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
use OpenSSL::Test qw/:DEFAULT srctop_dir bldtop_dir bldtop_file/;
use OpenSSL::Test::Utils;

BEGIN {
    setup("test_fipsinstall");
}
use lib srctop_dir('Configurations');
use lib bldtop_dir('.');
use platform;

plan skip_all => "Test only supported in a fips build" if disabled("fips");

plan tests => 6;

my $infile = bldtop_file('providers', platform->dso('fips'));
$ENV{OPENSSL_MODULES} = bldtop_dir("providers");

#fail if no module name
ok(!run(app(['openssl', 'fipsinstall', '-out', 'fips.conf', '-module',
             '-provider_name', 'fips',
             '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
             '-section_name', 'fips_install'])),
   "fipinstall fail");

# fail to Verify if the configuration file is missing
ok(!run(app(['openssl', 'fipsinstall', '-in', 'dummy.tmp', '-module', $infile,
             '-provider_name', 'fips', '-mac_name', 'HMAC',
             '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
             '-section_name', 'fips_install', '-verify'])),
   "fipinstall verify fail");


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

# Fail to Verify the fips.conf file if a different key is used
ok(!run(app(['openssl', 'fipsinstall', '-in', 'fips.conf', '-module', $infile,
             '-provider_name', 'fips', '-mac_name', 'HMAC',
             '-macopt', 'digest:SHA256', '-macopt', 'hexkey:01',
             '-section_name', 'fips_install', '-verify'])),
   "fipinstall verify fail bad key");

# Fail to Verify the fips.conf file if a different mac digest is used
ok(!run(app(['openssl', 'fipsinstall', '-in', 'fips.conf', '-module', $infile,
             '-provider_name', 'fips', '-mac_name', 'HMAC',
             '-macopt', 'digest:SHA512', '-macopt', 'hexkey:00',
             '-section_name', 'fips_install', '-verify'])),
   "fipinstall verify fail incorrect digest");
