#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
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
    setup("test_sde");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

my $no_sde = not exists($ENV{'OPENSSL_SDE_PATH'});
my $conf = srctop_file("test", 'default.cnf');

my @files = qw(
                evpciph_aes_sde.txt
              );

# SDE chip-check and CPUID for Intel(R)
my @cpus = qw(
             -mrm
             -pnr
             -nhm
             -wsm
             -snb
             -ivb
             -hsw
             -bdw
             -slt
             -slm
             -glm
             -glp
             -tnt
             -snr
             -skl
             -cnl
             -icl
             -skx
             -clx
             -cpx
             -icx
             -tgl
             -adl
             -mtl
             -rpl
             -spr
             -emr
             -gnr
             -gnr256
             -dmr
             -srf
             -arl
             -lnl
             -ptl
             -cwf
             -future
             );
#-p4
#-p4p

plan skip_all => 'Skip unless environment variable OPENSSL_SED_PATH is set'
    if $no_sde;

plan tests => scalar(@files) * scalar(@cpus);

my $sde = $ENV{'OPENSSL_SDE_PATH'};
foreach my $f ( @files ) {
  foreach my $cpu ( @cpus ) {
      ok(run(sdetest(["$sde", "$cpu", "--"],
                     ["evp_test", "-config", $conf, data_file("$f")])),
                      "running sde $cpu -- evp_test -config $conf $f");
  }
}
