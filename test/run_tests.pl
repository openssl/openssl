#! /usr/bin/perl

use strict;
use warnings;

use File::Spec::Functions qw/catdir catfile curdir abs2rel rel2abs/;
use File::Basename;
use Test::Harness qw/runtests $switches/;

my $top = $ENV{TOP};
my $recipesdir = catdir($top, "test", "recipes");
my $testlib = catdir($top, "test", "testlib");
my $utillib = catdir($top, "util");

# It seems that $switches is getting interpretted with 'eval' or something
# like that, and that we need to take care of backslashes or they will
# disappear along the way.
$testlib =~ s|\\|\\\\|g if $^O eq "MSWin32";
$utillib =~ s|\\|\\\\|g if $^O eq "MSWin32";

# Test::Harness provides the variable $switches to give it
# switches to be used when it calls our recipes.
$switches = "-w \"-I$testlib\" \"-I$utillib\"";

my @tests = ( "alltests" );
if (@ARGV) {
    @tests = @ARGV;
}
my $list_mode = scalar(grep /^list$/, @tests) != 0;
if (grep /^alltests|list$/, @tests) {
    @tests = grep {
	basename($_) =~ /^[0-9][0-9]-[^\.]*\.t$/
    } glob(catfile($recipesdir,"*.t"));
} else {
    my @t = ();
    foreach (@tests) {
	push @t, grep {
	    basename($_) =~ /^[0-9][0-9]-[^\.]*\.t$/
	} glob(catfile($recipesdir,"*-$_.t"));
    }
    @tests = @t;
}

if ($list_mode) {
    @tests = map { $_ = basename($_); $_ =~ s/^[0-9][0-9]-//; $_ =~ s/\.t$//;
                   $_ } @tests;
    print join("\n", @tests), "\n";
} else {
    @tests = map { abs2rel($_, rel2abs(curdir())); } @tests;

    runtests(sort @tests);
}
