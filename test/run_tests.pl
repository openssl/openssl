#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

# Recognise VERBOSE and V which is common on other projects.
BEGIN {
    $ENV{HARNESS_VERBOSE} = "yes" if $ENV{VERBOSE} || $ENV{V};
}

use File::Spec::Functions qw/catdir catfile curdir abs2rel rel2abs/;
use File::Basename;
use if $^O ne "VMS", 'File::Glob' => qw/glob/;
use Test::Harness qw/runtests $switches/;

my $srctop = $ENV{SRCTOP} || $ENV{TOP};
my $bldtop = $ENV{BLDTOP} || $ENV{TOP};
my $recipesdir = catdir($srctop, "test", "recipes");
my $testlib = catdir($srctop, "test", "testlib");
my $utillib = catdir($srctop, "util");

# It seems that $switches is getting interpreted with 'eval' or something
# like that, and that we need to take care of backslashes or they will
# disappear along the way.
$testlib =~ s|\\|\\\\|g if $^O eq "MSWin32";
$utillib =~ s|\\|\\\\|g if $^O eq "MSWin32";

# Test::Harness provides the variable $switches to give it
# switches to be used when it calls our recipes.
$switches = "-w \"-I$testlib\" \"-I$utillib\"";

my @alltests = find_matching_tests("*");
my %tests = ();

my $initial_arg = 1;
foreach my $arg (@ARGV ? @ARGV : ('alltests')) {
    if ($arg eq 'list') {
	foreach (@alltests) {
	    (my $x = basename($_)) =~ s|^[0-9][0-9]-(.*)\.t$|$1|;
	    print $x,"\n";
	}
	exit 0;
    }
    if ($arg eq 'alltests') {
	warn "'alltests' encountered, ignoring everything before that...\n"
	    unless $initial_arg;
	%tests = map { $_ => 1 } @alltests;
    } elsif ($arg =~ m/^(-?)(.*)/) {
	my $sign = $1;
	my $test = $2;
	my @matches = find_matching_tests($test);

	# If '-foo' is the first arg, it's short for 'alltests -foo'
	if ($sign eq '-' && $initial_arg) {
	    %tests = map { $_ => 1 } @alltests;
	}

	if (scalar @matches == 0) {
	    warn "Test $test found no match, skipping ",
		($sign eq '-' ? "removal" : "addition"),
		"...\n";
	} else {
	    foreach $test (@matches) {
		if ($sign eq '-') {
		    delete $tests{$test};
		} else {
		    $tests{$test} = 1;
		}
	    }
	}
    } else {
	warn "I don't know what '$arg' is about, ignoring...\n";
    }

    $initial_arg = 0;
}

runtests(map { abs2rel($_, rel2abs(curdir())); } sort keys %tests);

sub find_matching_tests {
    my ($glob) = @_;

    return glob(catfile($recipesdir,"*-$glob.t"));
}
