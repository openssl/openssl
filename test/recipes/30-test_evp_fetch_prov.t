#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT bldtop_dir srctop_file srctop_dir bldtop_file);
use OpenSSL::Test::Utils;

BEGIN {
setup("test_evp_fetch_prov");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');
use platform;

my @types = ( "digest", "cipher" );

plan tests => 2 + 16 * scalar(@types);

$ENV{OPENSSL_MODULES} = bldtop_dir("providers");
$ENV{OPENSSL_CONF_INCLUDE} = bldtop_dir("providers");

my $infile = bldtop_file('providers', platform->dso('fips'));
ok(run(app(['openssl', 'fipsinstall', '-out', bldtop_file('providers', 'fipsinstall.conf'),
            '-module', $infile,
            '-provider_name', 'fips', '-mac_name', 'HMAC',
            '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
            '-section_name', 'fips_sect'])), "fipinstall");

# Do implicit fetch using the default context
ok(run(test(["evp_fetch_prov_test", "-defaultctx"])),
    "running evp_fetch_prov_test using implicit fetch using the default libctx");

foreach my $alg(@types) {
   
   $ENV{OPENSSL_CONF} = srctop_file("test", "default.cnf");
   ok(run(test(["evp_fetch_prov_test", "-type", "$alg"])),
       "running evp_fetch_prov_test using implicit fetch using a created libctx");
   ok(run(test(["evp_fetch_prov_test", "-type", "$alg", "default"])),
       "running evp_fetch_prov_test with implicit fetch using default provider loaded");
   ok(run(test(["evp_fetch_prov_test", "-type", "$alg", "-property", "default=yes", "default"])),
       "running evp_fetch_prov_test with $alg fetch 'default=yes' using default provider loaded");
   ok(run(test(["evp_fetch_prov_test", "-type", "$alg", "-property", "fips=no", "default"])),
       "running evp_fetch_prov_test with $alg fetch 'fips=no' using default provider loaded"); 
   ok(run(test(["evp_fetch_prov_test", "-type", "$alg", "-property", "default=no", "-fetchfail", "default"])),
       "running evp_fetch_prov_test with $alg fetch 'default=no' using default provider loaded should fail");
   ok(run(test(["evp_fetch_prov_test", "-type", "$alg", "-property", "fips=yes", "-fetchfail", "default"])),
       "running evp_fetch_prov_test with $alg fetch 'fips=yes' using default provider loaded should fail");
   
   $ENV{OPENSSL_CONF} = srctop_file("test", "fips.cnf");
   ok(run(test(["evp_fetch_prov_test", "-type", "$alg", "-property", "", "fips"])),
       "running evp_fetch_prov_test with $alg fetch '' using loaded fips provider");
   ok(run(test(["evp_fetch_prov_test", "-type", "$alg", "-property", "fips=yes", "fips"])),
       "running evp_fetch_prov_test with $alg fetch 'fips=yes' using loaded fips provider");
   ok(run(test(["evp_fetch_prov_test", "-type", "$alg", "-property", "default=no", "fips"])),
       "running evp_fetch_prov_test with $alg fetch 'default=no' using loaded fips provider");
   ok(run(test(["evp_fetch_prov_test", "-type", "$alg", "-property", "default=yes", "-fetchfail", "fips"])),
       "running evp_fetch_prov_test with $alg fetch 'default=yes' using loaded fips provider should fail");
   ok(run(test(["evp_fetch_prov_test", "-type", "$alg", "-property", "fips=no", "-fetchfail", "fips"])),
       "running evp_fetch_prov_test with $alg fetch 'fips=no' using loaded fips provider should fail");            
   
   $ENV{OPENSSL_CONF} = srctop_file("test", "default-and-fips.cnf");
   ok(run(test(["evp_fetch_prov_test", "-type", "$alg", "-property", "", "default", "fips"])),
       "running evp_fetch_prov_test with $alg fetch '' using loaded default & fips provider");
   ok(run(test(["evp_fetch_prov_test", "-type", "$alg", "-property", "default=no", "default", "fips"])),
       "running evp_fetch_prov_test with $alg fetch 'default=no' using loaded default & fips provider");
   ok(run(test(["evp_fetch_prov_test", "-type", "$alg", "-property", "default=yes", "default", "fips"])),
       "running evp_fetch_prov_test with $alg fetch 'default=yes' using loaded default & fips provider");
   ok(run(test(["evp_fetch_prov_test", "-type", "$alg", "-property", "fips=no", "default", "fips"])),
       "running evp_fetch_prov_test with $alg fetch 'fips=no' using loaded default & fips provider");
   ok(run(test(["evp_fetch_prov_test", "-type", "$alg", "-property", "fips=yes", "default", "fips"])),
       "running evp_fetch_prov_test with $alg fetch 'fips=yes' using loaded default & fips provider");
}