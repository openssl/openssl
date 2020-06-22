#! /usr/bin/env perl
# Copyright 2015-2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT data_file bldtop_dir srctop_file srctop_dir bldtop_file);
use OpenSSL::Test::Utils;

BEGIN {
    setup("test_evp");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');
use platform;

my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);
my $no_legacy = disabled('legacy') || ($ENV{NO_LEGACY} // 0);

# Default config depends on if the legacy module is built or not
my $defaultcnf = $no_legacy ? 'default.cnf' : 'default-and-legacy.cnf';

my @configs = ( $defaultcnf );
# Only add the FIPS config if the FIPS module has been built
push @configs, 'fips.cnf' unless $no_fips;

# A list of tests that run with both the default and fips provider.
my @files = qw( evpciph.txt evpdigest.txt evpccmcavs.txt evppkey.txt
                evppkey_rsa.txt evppkey_dsa.txt evppkey_ecdsa.txt
                evppkey_ecc.txt evppkey_ecdh.txt evppkey_ffdhe.txt
                evppkey_kas.txt evppkey_ecx.txt evppkey_brainpool.txt
                evpcase.txt evpmac.txt evppbe.txt evprand.txt );

# A list of tests that only run with the default provider
# (i.e. The algorithms are not present in the fips provider)
my @defltfiles = qw( evpencod.txt evppkey_kdf.txt
                     evpciph_bf.txt evpciph_chacha.txt evpciph_seed.txt
                     evpaessiv.txt evpciph_cast5.txt evpciph_idea.txt
                     evpciph_sm4.txt evpciph_des.txt evpciph_rc2.txt
                     evpciph_rc4.txt evpciph_rc5.txt evpmd_md2.txt
                     evpmd_mdc2.txt);

my @sm2files = qw( evppkey_sm2.txt );
push @defltfiles, @sm2files unless disabled("sm2");

plan tests =>
    ($no_fips ? 0 : 1)          # FIPS install test
    + (scalar(@configs) * scalar(@files))
    + scalar(@defltfiles);

unless ($no_fips) {
    my $infile = bldtop_file('providers', platform->dso('fips'));

    ok(run(app(['openssl', 'fipsinstall',
                '-out', bldtop_file('providers', 'fipsmodule.cnf'),
                '-module', $infile])),
       "fipsinstall");
}

foreach (@configs) {
    $ENV{OPENSSL_CONF} = srctop_file("test", $_);

    foreach my $f ( @files ) {
        ok(run(test(["evp_test", data_file("$f")])),
           "running evp_test $f (using OPENSSL_CONF=$ENV{OPENSSL_CONF})");
    }
}

$ENV{OPENSSL_CONF} = srctop_file("test", $defaultcnf);

foreach my $f ( @defltfiles ) {
    ok(run(test(["evp_test", data_file("$f")])),
       "running evp_test $f (using OPENSSL_CONF=$ENV{OPENSSL_CONF})");
}
