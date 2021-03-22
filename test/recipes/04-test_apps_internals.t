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

setup('test_apps_internals');

my @app_rename_tests = (
    { 
        description => 'rename the testfile to a different name',
        srcname => 'simple.txt',
        dstname => 'simple1.txt',
        exit_expected => 1,
        src_expected => 0,
        dst_expected => 1
    },
    { 
        description => 'rename the testfile but provide the same name as destination',
        srcname => 'simple.txt',
        dstname => 'simple.txt',
        exit_expected => 1,
        src_expected => 1,
        dst_expected => 1
    },
    { 
        description => 'call app_rename but provide not existing source file',
        srcname => 'missing.txt',
        dstname => 'simple.txt',
        exit_expected => 0,
        src_expected => 0,
        dst_expected => 0
    },
    { 
        description => 'rename the testfile but use current directory as destination',
        srcname => 'simple.txt',
        dstname => '.',
        exit_expected => 0,
        src_expected => 1,
        dst_expected => 1
    }
);

my @unsupported_commands = (
    { 
        command => 'unsupported'
    }
);
 
# every "test_app_rename" makes 2 checks
plan tests => 3 * scalar(@app_rename_tests) +
              1 * scalar(@unsupported_commands);


foreach my $test (@app_rename_tests) {
    test_updatedb($test);
}
foreach my $test (@unsupported_commands) {
    test_unsupported_commands($test);
}


################### subs to do tests per supported command ################

sub test_unsupported_commands {
    my ($opts) = @_;

    run(
        test(['apps_internals_test',
                $opts->{command}
        ]),
        capture => 0,
        statusvar => \my $exit
    );

    is($exit, 0, "command '".$opts->{command}."' completed without an error");
}

sub test_updatedb {
    my ($opts) = @_;
    my $srcexists = 0;
    my $dstexists = 0;

    copy(data_file($opts->{srcname}), $opts->{srcname});
    run(
        test(['apps_internals_test',
                'app_rename',
                $opts->{srcname},
                $opts->{dstname}
        ]),
        statusvar => \my $exit
    );

    if ( -e $opts->{srcname}) {
        $srcexists = 1;
    }
    if ( -e $opts->{dstname}) {
        $dstexists = 1;
        unlink($opts->{dstname});
    }
    if ( -e $opts->{srcname}) {
        unlink($opts->{srcname});
    }

    is($exit, $opts->{exit_expected}, "apps_internals_test: exit code is '$exit' insted of '".
        $opts->{exit_expected}."' (".$opts->{description}.")");
    is($srcexists, $opts->{src_expected}, "apps_internals_test: srcfile is '$srcexists' instead of '".
        $opts->{src_expected}."' after rename (".$opts->{description}.")");
    is($dstexists, $opts->{dst_expected}, "apps_internals_test: dstfile is '$dstexists' instead of '".
        $opts->{dst_expected}."' after rename (".$opts->{description}.")");
}

