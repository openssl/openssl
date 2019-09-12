#! /usr/bin/env perl
# Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Reads one or more template files and runs it through Text::Template
#
# It is assumed that this scripts is called with -Mconfigdata, a module
# that holds configuration data in %config

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/perl";
use OpenSSL::fallback "$FindBin::Bin/../external/perl/MODULES.txt";
use Getopt::Std;
use OpenSSL::Template;

# We actually expect to get the following hash tables from configdata:
#
#    %config
#    %target
#    %withargs
#    %unified_info
#
# We just do a minimal test to see that we got what we expected.
# $config{target} must exist as an absolute minimum.
die "You must run this script with -Mconfigdata\n"
    if !exists($config{target});

# Check options ######################################################

my %opts = ();

# -o ORIGINATOR
#		declares ORIGINATOR as the originating script.
getopt('o', \%opts);

my @autowarntext = ("WARNING: do not edit!",
                    "Generated"
                    . (defined($opts{o}) ? " by ".$opts{o} : "")
                    . (scalar(@ARGV) > 0 ? " from ".join(", ",@ARGV) : ""));

# Template setup #####################################################

my @template_settings =
    @ARGV
    ? map { { TYPE => 'FILE', SOURCE => $_, FILENAME => $_ } } @ARGV
    : ( { TYPE => 'FILEHANDLE', SOURCE => \*STDIN, FILENAME => '<stdin>' } );

# Engage! ############################################################

my $prepend = <<"_____";
use File::Spec::Functions;
_____
$prepend .= <<"_____" if defined $target{perl_platform};
use lib "$FindBin::Bin/../Configurations";
use lib '$config{builddir}';
use platform;
_____

foreach (@template_settings) {
    my $template = OpenSSL::Template->new(%$_);
    $template->fill_in(%$_,
                       OUTPUT => \*STDOUT,
                       HASH => { config => \%config,
                                 target => \%target,
                                 disabled => \%disabled,
                                 withargs => \%withargs,
                                 unified_info => \%unified_info,
                                 autowarntext => \@autowarntext },
                       PREPEND => $prepend,
                       # To ensure that global variables and functions
                       # defined in one template stick around for the
                       # next, making them combinable
                       PACKAGE => 'OpenSSL::safe');
}
