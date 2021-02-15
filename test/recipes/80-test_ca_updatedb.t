#! /usr/bin/env perl
# Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use POSIX;
use OpenSSL::Test qw/:DEFAULT data_file/;
use File::Copy;

setup('test_ca_updatedb');

my @tests = (
    { 
        description => 'updatedb called before the first certificate expires',
        filename => 'index.txt',
        copydb => 1,
        testdate => '990101000000Z',
        expirelist => []
    },
    { 
        description => 'updatedb called before Y2k',
        filename => 'index.txt',
        copydb => 0,
        testdate => '991201000000Z',
        expirelist => [ '1000' ]
    },
    { 
        description => 'updatedb called after year 2020',
        filename => 'index.txt',
        copydb => 0,
        testdate => '211201000000Z',
        expirelist => [ '1001' ]
    },
    { 
        description => 'updatedb called in year 2049 (last year with 2 digits)',
        filename => 'index.txt',
        copydb => 0,
        testdate => '491201000000Z',
        expirelist => [ '1002' ]
    },
    { 
        description => 'updatedb called in year 2050 (first year with 4 digits) before the last certificate expires',
        filename => 'index.txt',
        copydb => 0,
        testdate => '20500101000000Z',
        expirelist => [ ]
    },
    { 
        description => 'updatedb called after the last certificate expired',
        filename => 'index.txt',
        copydb => 0,
        testdate => '20501201000000Z',
        expirelist => [ '1003' ]
    },
    { 
        description => 'updatedb called for the first time after the last certificate expired',
        filename => 'index.txt',
        copydb => 1,
        testdate => '20501201000000Z',
        expirelist => [ '1000', 
                        '1001',
                        '1002',
                        '1003' ]
    }
);

# every "test_updatedb" makes 3 checks
plan tests => 3 * scalar(@tests);

foreach my $test (@tests) {
    test_updatedb($test);
}


sub test_updatedb {
    my ($opts) = @_;
    my $amt = scalar(@{$opts->{expirelist}});
    my @output;
    my $expirelistcorrect = 1;
    my $cert;

    if ($opts->{copydb}) {
        copy(data_file('index.txt'), 'index.txt');
    }

    @output = run(
        test(['ca_updatedb',
            $opts->{filename},
            $opts->{testdate}
        ]),
        capture => 1,
        statusvar => \my $exit
    );

    foreach my $tmp (@output) {
        ($cert)=$tmp=~/^([0-9A-F]+)=Expired/;
        my $expirefound = 0;
        foreach my $expire (@{$opts->{expirelist}}) {
            if ($expire eq $cert) {
                $expirefound = 1;
            }
        }
        if ($expirefound != 1) {
            $expirelistcorrect = 0;
        }
    }

    is($exit, 1, "ca_updatedb: returned EXIT_FAILURE (".$opts->{description}.")");
    is(scalar(@output), $amt, "ca_updatedb: amount of expired certificated differs from expected amount (".$opts->{description}.")");
    is($expirelistcorrect, 1, "ca_updatedb: list of expired certificated differs from expected list (".$opts->{description}.")");
}

