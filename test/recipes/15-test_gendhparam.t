#! /usr/bin/env perl
# Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test;
use OpenSSL::Test::Utils;

setup("test_gendhparam");

my @testdata = (
    {
        algorithm => 'DH',
        pkeyopts => [ "type:fips186_4", 'digest:SHA256', 'gindex:1' ],
        expect => [ 'BEGIN DH PARAMETERS', 'gindex:', 'pcounter:', 'SEED:' ],
        message   => 'DH fips186_4 param gen',
    },
    {
        algorithm => 'DHX',
        pkeyopts => [ 'type:fips186_2', 'pbits:1024', 'qbits:160' ],
        message   => 'DHX fips186_2 param gen with a selected p and q size',
        expect => [ 'BEGIN X9.42 DH PARAMETERS', 'h:', 'pcounter:', 'SEED:' ],
    },
    {
        algorithm => 'DHX',
        pkeyopts => [ 'type:fips186_2', 'dh_paramgen_prime_len:1024', 'dh_paramgen_subprime_len:160' ],
        message   => 'DHX fips186_2 param gen with a selected p and q size using aliased',
        expect => [ "BEGIN X9.42 DH PARAMETERS" ],
    },
    {
        algorithm => 'DH',
        pkeyopts => [ 'type:fips186_2', 'dh_paramgen_prime_len:1024', 'dh_paramgen_subprime_len:160' ],
        message   => 'DH fips186_2 param gen with a selected p and q size using aliases should fail',
        expect => [ "ERROR" ],
    },
    {
        algorithm => 'DH',
        pkeyopts => [ 'group:ffdhe2048'],
        expect => [ 'BEGIN DH PARAMETERS', 'GROUP:' ],
        message   => 'DH named group ffdhe selection',
    },
    {
        algorithm => 'DH',
        pkeyopts => [ 'dh_param:ffdhe8192'],
        expect => [ 'BEGIN DH PARAMETERS', 'GROUP:' ],
        message   => 'DH named group ffdhe selection using alias',
    },
    {
        algorithm => 'DH',
        pkeyopts => [ 'group:modp_3072'],
        expect => [ 'BEGIN DH PARAMETERS', 'GROUP:' ],
        message   => 'DH named group modp selection',
    },
    {
        algorithm => 'DH',
        pkeyopts => [ 'dh_param:modp_4096'],
        message   => 'DH named group modp selection using alias',
        expect => [ 'BEGIN DH PARAMETERS', 'GROUP:'],
    },
    {
        algorithm => 'DHX',
        pkeyopts => [ 'group:dh_2048_256' ],
        expect => [ 'BEGIN X9.42 DH PARAMETERS', 'GROUP:' ],
        message   => 'DHX RFC5114 named group selection',
    },
    {
        algorithm => 'DHX',
        pkeyopts => [ 'dh_param:dh_2048_224' ],
        expect => [ 'BEGIN X9.42 DH PARAMETERS', 'GROUP:' ],
        message   => 'DHX RFC5114 named group selection using alias',
    },
    {
        algorithm => 'DHX',
        pkeyopts => [ 'dh_rfc5114:2'],
        expect => [ 'BEGIN X9.42 DH PARAMETERS', 'GROUP:' ],
        message   => 'DHX RFC5114 named group selection using an id',
    },
# These tests using the safeprime generator were removed as they are slow..
#    {
#        algorithm => 'DH',
#        pkeyopts => [ 'type:generator', 'safeprime-generator:5'],
#        expect => [ 'BEGIN DH PARAMETERS', 'G:    5' ],
#        message   => 'DH safe prime generator',
#    },
#    {
#        algorithm => 'DH',
#        pkeyopts => [ 'dh_paramgen_type:0', 'dh_paramgen_generator:5'],
#        expect => [ 'BEGIN DH PARAMETERS', 'G:    5' ],
#        message   => 'DH safe prime generator using an alias',
#    },
);

plan tests => scalar @testdata;
plan skip_all => "DH isn't supported in this build" if disabled("dh");

foreach my $test (@testdata) {
    my $alg = $test->{algorithm};
    my $msg = $test->{message};
    my @testargs = @{ $test->{pkeyopts} };
    my @expected = @{ $test->{expect} };
    my @pkeyopts= ();
    foreach (@testargs) {
        push(@pkeyopts, '-pkeyopt');
        push(@pkeyopts, $_);
    }
    my @lines = run(app(['openssl', 'genpkey', '-genparam',
                          '-algorithm', $alg, '-text', @pkeyopts]),
                    capture => 1);
    ok(compareline(\@lines, \@expected), $msg);
}

# Check that the stdout output matches the expected value.
sub compareline {
    my ($ref_lines, $ref_expected) = @_;
    my @lines = @$ref_lines;
    my @expected = @$ref_expected;

    if (@lines == 0 and $expected[0] == 'ERROR') {
        return 1;
    }
    print "-----------------\n";
    foreach (@lines) {
        print $_;
    }
    print "-----------------\n";
    foreach my $ex (@expected) {
        if ( !grep { index($_, $ex) >= 0 }  @lines) {
            print "ERROR: Cannot find: $ex\n";
            return 0;
        }
    }
    return 1;
}
