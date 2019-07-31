#! /usr/bin/env perl
# Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT data_file bldtop_dir srctop_file);

setup("test_evp");

#TODO(3.0) We temporarily disable testing with the FIPS module while that
#          testing is broken
#my @configs = qw( default-and-legacy.cnf fips.cnf );
my @configs = qw( default-and-legacy.cnf );
my @files = qw( evpciph.txt evpdigest.txt evpencod.txt evpkdf.txt
    evppkey_kdf.txt evpmac.txt evppbe.txt evppkey.txt
    evppkey_ecc.txt evpcase.txt evpaessiv.txt evpccmcavs.txt );

plan tests => scalar(@configs) * scalar(@files);

$ENV{OPENSSL_MODULES} = bldtop_dir("providers");

foreach (@configs) {
    $ENV{OPENSSL_CONF} = srctop_file("test", $_);

    foreach my $f ( @files ) {
        ok(run(test(["evp_test", data_file("$f")])),
           "running evp_test $f");
    }
}
