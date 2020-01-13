#! /usr/bin/env perl
# Copyright 2019 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html

use strict;
use warnings;

use File::Spec;
use File::Copy;
use Opentls::Glob;
use Opentls::Test qw/:DEFAULT srctop_dir bldtop_dir bldtop_file/;
use Opentls::Test::Utils;

BEGIN {
    setup("test_fipsinstall");
}
use lib srctop_dir('Configurations');
use lib bldtop_dir('.');
use platform;

plan skip_all => "Test only supported in a fips build" if disabled("fips");

plan tests => 6;

my $infile = bldtop_file('providers', platform->dso('fips'));
$ENV{OPENtls_MODULES} = bldtop_dir("providers");

# fail if no module name
ok(!run(app(['opentls', 'fipsinstall', '-out', 'fips.conf', '-module',
             '-provider_name', 'fips',
             '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
             '-section_name', 'fips_install'])),
   "fipsinstall fail");

# fail to verify if the configuration file is missing
ok(!run(app(['opentls', 'fipsinstall', '-in', 'dummy.tmp', '-module', $infile,
             '-provider_name', 'fips', '-mac_name', 'HMAC',
             '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
             '-section_name', 'fips_install', '-verify'])),
   "fipsinstall verify fail");


# output a fips.conf file containing mac data
ok(run(app(['opentls', 'fipsinstall', '-out', 'fips.conf', '-module', $infile,
            '-provider_name', 'fips', '-mac_name', 'HMAC',
            '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
            '-section_name', 'fips_install'])),
   "fipsinstall");

# verify the fips.conf file
ok(run(app(['opentls', 'fipsinstall', '-in', 'fips.conf', '-module', $infile,
            '-provider_name', 'fips', '-mac_name', 'HMAC',
            '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
            '-section_name', 'fips_install', '-verify'])),
   "fipsinstall verify");

# fail to verify the fips.conf file if a different key is used
ok(!run(app(['opentls', 'fipsinstall', '-in', 'fips.conf', '-module', $infile,
             '-provider_name', 'fips', '-mac_name', 'HMAC',
             '-macopt', 'digest:SHA256', '-macopt', 'hexkey:01',
             '-section_name', 'fips_install', '-verify'])),
   "fipsinstall verify fail bad key");

# fail to verify the fips.conf file if a different mac digest is used
ok(!run(app(['opentls', 'fipsinstall', '-in', 'fips.conf', '-module', $infile,
             '-provider_name', 'fips', '-mac_name', 'HMAC',
             '-macopt', 'digest:SHA512', '-macopt', 'hexkey:00',
             '-section_name', 'fips_install', '-verify'])),
   "fipsinstall verify fail incorrect digest");
