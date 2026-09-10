#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Find;
use File::Spec::Functions qw(abs2rel);

use OpenSSL::Test qw(:DEFAULT bldtop_dir);
use OpenSSL::Test::Utils;

setup("test_unit");

my $unit_dir = bldtop_dir('test', 'unit');
my $exeext = '';

if ($^O eq 'MSWin32') {
    $exeext = '.exe';
    # The shared libraries (libcrypto/libssl DLLs) are only placed at the
    # build top and copied into apps/, test/ and fuzz/.  The unit test
    # executables live in nested directories under test/unit/, so add the
    # build top to PATH to let the loader find the DLLs.
    $ENV{PATH} = bldtop_dir() . ';' . ($ENV{PATH} // '');
}

my @tests = ();
if (-d $unit_dir) {
    find({
        wanted => sub {
            return unless -f $_;
            my $base = $_;
            if ($exeext ne '') {
                # require + strip .exe
                return unless $base =~ s/\Q$exeext\E$//;
            } else {
                return unless -x $_;
            }
            return unless $base =~ m|/test_[^/]*$|;
            # reject .pdb/.obj/etc
            return if $base =~ m|\.\w+$|;
            push @tests, $_;
        },
        no_chdir => 1,
    }, $unit_dir);
}

@tests = sort @tests;

plan skip_all => "No unit tests built (enable-unit-tests not set?)"
    unless @tests;

plan tests => scalar @tests;

foreach my $test_bin (@tests) {
    my $name = abs2rel($test_bin, $unit_dir);
    ok(run(cmd([$test_bin])), "unit: $name");
}
