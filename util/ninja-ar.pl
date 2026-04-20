#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use Getopt::Long;
use Text::ParseWords;

my $ar = undef;
my $arflags = '';
my $ranlib = '';
my $out = undef;
my $rsp = undef;

GetOptions('ar=s'      => \$ar,
           'arflags=s' => \$arflags,
           'ranlib=s'  => \$ranlib,
           'out=s'     => \$out,
           'rsp=s'     => \$rsp)
    or die "Error in command line arguments\n";

die "No archiver was specified\n" unless defined $ar && $ar ne '';
die "No output archive was specified\n" unless defined $out && $out ne '';
die "No response file was specified\n" unless defined $rsp && $rsp ne '';

open my $rfh, '<', $rsp or die "Trying to read $rsp: $!\n";
my $rspdata = do { local $/; <$rfh> };
close $rfh;

my @objs = grep { $_ ne '' } shellwords($rspdata);
die "No object files given for $out\n" unless @objs;

unlink $out if -e $out;

my @arcmd = shellwords($ar);
my @arflags = shellwords($arflags);
my $max_per_call = 500;

while (@objs) {
    my @chunk = splice @objs, 0, $max_per_call;
    system { $arcmd[0] } @arcmd, @arflags, $out, @chunk;
    die "Archiver command failed for $out\n" if $? != 0;
}

if (defined $ranlib && $ranlib ne '' && $ranlib ne 'true') {
    my @ranlibcmd = shellwords($ranlib);
    system { $ranlibcmd[0] } @ranlibcmd, $out;
    warn "ranlib failed for $out; ignoring\n" if $? != 0;
}

exit 0;
