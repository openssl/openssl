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

plan tests => 12;

my $infile = bldtop_file('providers', platform->dso('fips'));
$ENV{OPENSSL_MODULES} = bldtop_dir("providers");

# fail if no module name
ok(!run(app(['openssl', 'fipsinstall', '-out', 'fips.cnf', '-module',
             '-provider_name', 'fips',
             '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
             '-section_name', 'fips_install'])),
   "fipsinstall fail");

# fail to verify if the configuration file is missing
ok(!run(app(['openssl', 'fipsinstall', '-in', 'dummy.tmp', '-module', $infile,
             '-provider_name', 'fips', '-mac_name', 'HMAC',
             '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
             '-section_name', 'fips_install', '-verify'])),
   "fipsinstall verify fail");


# output a fips.cnf file containing mac data
ok(run(app(['openssl', 'fipsinstall', '-out', 'fips.cnf', '-module', $infile,
            '-provider_name', 'fips', '-mac_name', 'HMAC',
            '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
            '-section_name', 'fips_install'])),
   "fipsinstall");

# verify the fips.cnf file
ok(run(app(['openssl', 'fipsinstall', '-in', 'fips.cnf', '-module', $infile,
            '-provider_name', 'fips', '-mac_name', 'HMAC',
            '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
            '-section_name', 'fips_install', '-verify'])),
   "fipsinstall verify");

# fail to verify the fips.cnf file if a different key is used
ok(!run(app(['openssl', 'fipsinstall', '-in', 'fips.cnf', '-module', $infile,
             '-provider_name', 'fips', '-mac_name', 'HMAC',
             '-macopt', 'digest:SHA256', '-macopt', 'hexkey:01',
             '-section_name', 'fips_install', '-verify'])),
   "fipsinstall verify fail bad key");

# fail to verify the fips.cnf file if a different mac digest is used
ok(!run(app(['openssl', 'fipsinstall', '-in', 'fips.cnf', '-module', $infile,
             '-provider_name', 'fips', '-mac_name', 'HMAC',
             '-macopt', 'digest:SHA512', '-macopt', 'hexkey:00',
             '-section_name', 'fips_install', '-verify'])),
   "fipsinstall verify fail incorrect digest");

# corrupt the module hmac
ok(!run(app(['openssl', 'fipsinstall', '-out', 'fips.cnf', '-module', $infile,
            '-provider_name', 'fips', '-mac_name', 'HMAC',
            '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
            '-section_name', 'fips_install', '-corrupt_desc', 'HMAC'])),
   "fipsinstall fails when the module integrity is corrupted");

# corrupt the first digest
ok(!run(app(['openssl', 'fipsinstall', '-out', 'fips.cnf', '-module', $infile,
            '-provider_name', 'fips', '-mac_name', 'HMAC',
            '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
            '-section_name', 'fips_install', '-corrupt_desc', 'SHA1'])),
   "fipsinstall fails when the digest result is corrupted");

# corrupt another digest
ok(!run(app(['openssl', 'fipsinstall', '-out', 'fips.cnf', '-module', $infile,
            '-provider_name', 'fips', '-mac_name', 'HMAC',
            '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
            '-section_name', 'fips_install', '-corrupt_desc', 'SHA3'])),
   "fipsinstall fails when the digest result is corrupted");

# corrupt DRBG
ok(!run(app(['openssl', 'fipsinstall', '-out', 'fips.cnf', '-module', $infile,
            '-provider_name', 'fips', '-mac_name', 'HMAC',
            '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
            '-section_name', 'fips_install', '-corrupt_desc', 'CTR'])),
   "fipsinstall fails when the DRBG CTR result is corrupted");

# corrupt a KAS test
ok(!run(app(['openssl', 'fipsinstall', '-out', 'fips.conf', '-module', $infile,
            '-provider_name', 'fips', '-mac_name', 'HMAC',
            '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
            '-section_name', 'fips_install',
            '-corrupt_desc', 'DH',
            '-corrupt_type', 'KAT_KA'])),
   "fipsinstall fails when the kas result is corrupted");

# corrupt a Signature test
ok(!run(app(['openssl', 'fipsinstall', '-out', 'fips.conf', '-module', $infile,
            '-provider_name', 'fips', '-mac_name', 'HMAC',
            '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
            '-section_name', 'fips_install',
            '-corrupt_desc', 'DSA',
            '-corrupt_type', 'KAT_Signature'])),
   "fipsinstall fails when the signature result is corrupted");
