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

my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);

my @types = ( "digest", "cipher" );

$ENV{OPENSSL_MODULES} = bldtop_dir("providers");
$ENV{OPENSSL_CONF_INCLUDE} = bldtop_dir("providers");

my @setups = ();
my @testdata = (
    { config    => srctop_file("test", "default.cnf"),
      providers => [ 'default' ],
      tests  => [ { providers => [] },
                  { },
                  { args      => [ '-property', 'default=yes' ],
                    message   => 'using property "default=yes"' },
                  { args      => [ '-property', 'fips=no' ],
                    message   => 'using property "fips=no"' },
                  { args      => [ '-property', 'default=no', '-fetchfail' ],
                    message   =>
                        'using property "default=no" is expected to fail' },
                  { args      => [ '-property', 'fips=yes', '-fetchfail' ],
                    message   =>
                        'using property "fips=yes" is expected to fail' } ] }
);

unless ($no_fips) {
    push @setups, {
        cmd     => app(['openssl', 'fipsinstall',
                        '-out', bldtop_file('providers', 'fipsinstall.conf'),
                        '-module', bldtop_file('providers', platform->dso('fips')),
                        '-provider_name', 'fips', '-mac_name', 'HMAC',
                        '-macopt', 'digest:SHA256', '-macopt', 'hexkey:00',
                        '-section_name', 'fips_sect']),
        message => "fipsinstall"
    };
    push @testdata, (
        { config    => srctop_file("test", "fips.cnf"),
          providers => [ 'fips' ],
          tests     => [
              { args    => [ '-property', '' ] },
              { args    => [ '-property', 'fips=yes' ],
                message => 'using property "fips=yes"' },
              { args    => [ '-property', 'default=no' ],
                message => 'using property "default = no"' },
              { args      => [ '-property', 'default=yes', '-fetchfail' ],
                message   =>
                    'using property "default=yes" is expected to fail' },
              { args      => [ '-property', 'fips=no', '-fetchfail' ],
                message   =>
                    'using property "fips=no" is expected to fail' } ] },
        { config    => srctop_file("test", "default-and-fips.cnf"),
          providers => [ 'default', 'fips' ],
          tests     => [
              { args    => [ '-property', '' ] },
              { args      => [ '-property', 'default=no' ],
                message   => 'using property "default=no"' },
              { args      => [ '-property', 'default=yes' ],
                message   => 'using property "default=yes"' },
              { args      => [ '-property', 'fips=no' ],
                message   => 'using property "fips=no"' },
              { args      => [ '-property', 'fips=yes' ],
                message   => 'using property "fips=yes"' } ] }
    );
}

my $testcount = 0;
foreach (@testdata) {
    $testcount += scalar @{$_->{tests}};
}

plan tests => 1 + scalar @setups + $testcount * scalar(@types);

ok(run(test(["evp_fetch_prov_test", "-defaultctx"])),
   "running evp_fetch_prov_test using the default libctx");

foreach my $setup (@setups) {
    ok(run($setup->{cmd}), $setup->{message});
}

foreach my $alg (@types) {
    foreach my $testcase (@testdata) {
        $ENV{OPENSSL_CONF} = $testcase->{config};
        foreach my $test (@{$testcase->{tests}}) {
            my @testproviders =
                @{ $test->{providers} // $testcase->{providers} };
            my $testprovstr = @testproviders
                ? ' and loaded providers ' . join(' & ',
                                                  map { "'$_'" } @testproviders)
                : '';
            my @testargs = @{ $test->{args} // [] };
            my $testmsg =
                defined $test->{message} ? ' '.$test->{message} : '';

            my $message =
                "running evp_fetch_prov_test with $alg$testprovstr$testmsg";

            ok(run(test(["evp_fetch_prov_test", "-type", "$alg",
                         @testargs, @testproviders])),
               $message);
        }
    }
}
