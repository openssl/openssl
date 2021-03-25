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
    },
    { 
        description => 'no parameters',
        srcname => '',
        dstname => '',
        exit_expected => 0,
        src_expected => 0,
        dst_expected => 0
    },
    { 
        description => 'only one parameter but nonexisting file',
        srcname => 'missing',
        dstname => '',
        exit_expected => 0,
        src_expected => 0,
        dst_expected => 0
    },
    { 
        description => 'only one parameter, existing file',
        srcname => 'simple.txt',
        dstname => '',
        exit_expected => 0,
        src_expected => 1,
        dst_expected => 0
    }
);

my @app_strcasecmp_tests = (
    { 
        description => 'app_strcasecmp, first string is less than the second, same case',
        string1 => 'string1',
        string2 => 'string2',
        amt_results_expected => 1,
        exit_expected => 1,
        result_expected => -1
    },
    { 
        description => 'app_strcasecmp, first string is less than the second, different case',
        string1 => 'STRING1',
        string2 => 'string2',
        amt_results_expected => 1,
        exit_expected => 1,
        result_expected => -1
    },
    { 
        description => 'app_strcasecmp, first string is bigger than the second, same case',
        string1 => 'string2',
        string2 => 'string1',
        amt_results_expected => 1,
        exit_expected => 1,
        result_expected => 1
    },
    { 
        description => 'app_strcasecmp, first string is bigger than the second, different case',
        string1 => 'STRING2',
        string2 => 'string1',
        amt_results_expected => 1,
        exit_expected => 1,
        result_expected => 1
    },
    { 
        description => 'app_strcasecmp, identical strings, same case',
        string1 => 'string1',
        string2 => 'string1',
        amt_results_expected => 1,
        exit_expected => 1,
        result_expected => 0
    },
    { 
        description => 'app_strcasecmp, identical, different case',
        string1 => 'STRING1',
        string2 => 'string1',
        amt_results_expected => 1,
        exit_expected => 1,
        result_expected => 0
    },
    { 
        description => 'app_strcasecmp, identical strings with blanks',
        string1 => 'The quick brown fox jumps over the lazy dog',
        string2 => 'The quick brown fox jumps over the lazy dog',
        amt_results_expected => 1,
        exit_expected => 1,
        result_expected => 0
    }
);

my @file_io_tests = (
    {
        description => 'read a simple line from a file',
        filenamecreate => 'testfile.txt',
        filenamespecify => 'testfile.txt',
        filecontent => 'Prall vom Whisky flog Quax den Jet zu Bruch.',
        output_expected => 'Prall vom Whisky flog Quax den Jet zu Bruch.',
        exit_expected => 1
    },
    {
        description => 'don\'t specify filename',
        filenamecreate => 'testfile.txt',
        filenamespecify => '',
        filecontent => 'Prall vom Whisky flog Quax den Jet zu Bruch.',
        output_expected => '',
        exit_expected => 0
    },
    {
        description => 'Specify invalid file',
        filenamecreate => 'testfile.txt',
        filenamespecify => 'invalid.txt',
        filecontent => 'Prall vom Whisky flog Quax den Jet zu Bruch.',
        output_expected => '',
        exit_expected => 0
    }
);

my @unsupported_commands = (
    { 
        command => 'unsupported'
    }
);
 
# every "test_app_rename" makes 3 checks
plan tests => 3 * scalar(@app_rename_tests) +
              3 * scalar(@app_strcasecmp_tests) +
              2 * 2 * scalar(@file_io_tests) +
              1 * scalar(@unsupported_commands);


foreach my $test (@app_rename_tests) {
    test_app_rename($test);
}
foreach my $test (@app_strcasecmp_tests) {
    test_app_strcasecmp($test);
}
foreach my $test (@file_io_tests) {
    test_file_io('posix_file_io', $test);
}
foreach my $test (@file_io_tests) {
    test_file_io('app_fdopen', $test);
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

sub test_app_rename {
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

    is($exit, $opts->{exit_expected}, "apps_internals_test/app_rename: exit code is '$exit' instead of '".
        $opts->{exit_expected}."' (".$opts->{description}.")");
    is($srcexists, $opts->{src_expected}, "apps_internals_test/app_rename: srcfile is '$srcexists' instead of '".
        $opts->{src_expected}."' after rename (".$opts->{description}.")");
    is($dstexists, $opts->{dst_expected}, "apps_internals_test/app_rename: dstfile is '$dstexists' instead of '".
        $opts->{dst_expected}."' after rename (".$opts->{description}.")");
}

sub test_app_strcasecmp {
    my ($opts) = @_;
    my @output;

    @output = run(
        test(['apps_internals_test',
            'app_strcasecmp',
            $opts->{string1},
            $opts->{string2}
        ]),
        capture => 1,
        statusvar => \my $exit
    );

    my $rv = 0;
    my $amt = 0;
    foreach my $tmp (@output) {
        if ($tmp =~ /^[\s]+#\sResult:\s'([\-0-9]+[0-9]*)'$/) {
            ($rv) = $tmp =~ /^[\s]+#\sResult:\s'([\-0-9]+[0-9]*)'$/;
            $amt++;
        }
    }

    is($amt, $opts->{amt_results_expected}, "apps_internals_test/test_app_strcasecmp: strange amount of results: '$amt' instead of '".
        $opts->{amt_results_expected}."' (".$opts->{description}.")");
    is($exit, $opts->{exit_expected}, "apps_internals_test/test_app_strcasecmp: exit code is '$exit' instead of '".
        $opts->{exit_expected}."' (".$opts->{description}.")");
    is($rv, $opts->{result_expected}, "apps_internals_test/test_app_strcasecmp: result is '$rv' instead of '".
        $opts->{result_expected}."' (".$opts->{description}.")");
}

sub test_file_io {
    my $command = shift;
    my ($opts) = @_;
    my @output;

    open(my $fh, '>', $opts->{filenamecreate});
    print $fh $opts->{filecontent};
    close $fh;
    @output = run(
        test(['apps_internals_test',
            $command,
            $opts->{filenamespecify}
        ]),
        capture => 1,
        statusvar => \my $exit
    );
    unlink $opts->{filenamecreate};
    my $rv = '';
    foreach my $tmp (@output) {
        if ($tmp =~ /^[\s]+#\sContent:\s'/) {
            ($rv) = $tmp =~ /^[\s]+#\sContent:\s'([^']*)'/;
        }
    }
    is($rv, $opts->{output_expected}, "apps_internals_test/test_posix_file_io: result is '$rv' instead of '".
        $opts->{output_expected}."' (".$opts->{description}.")");
    is($exit, $opts->{exit_expected}, "apps_internals_test/test_posix_file_io: exit code is '$exit' instead of '".
        $opts->{exit_expected}."' (".$opts->{description}.")");
}

