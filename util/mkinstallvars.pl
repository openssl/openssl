#! /usr/bin/env perl
# Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# All variables are supposed to come from Makefile, in environment variable
# form, or passed as variable assignments on the command line.
# The result is a Perl module creating the package OpenSSL::safe::installdata.

use File::Spec;

# These are expected to be set up as absolute directories
my @absolutes = qw(PREFIX);
# These may be absolute directories, and if not, they are expected to be set up
# as subdirectories to PREFIX
my @subdirs = qw(BINDIR LIBDIR INCLUDEDIR ENGINESDIR MODULESDIR APPLINKDIR);

my %keys = ();
foreach (@ARGV) {
    (my $k, my $v) = m|^([^=]*)=(.*)$|;
    $keys{$k} = 1;
    $ENV{$k} = $v;
}
foreach my $k (sort keys %keys) {
    my $v = $ENV{$k};
    $v = File::Spec->rel2abs($v) if $v && grep { $k eq $_ } @absolutes;
    $ENV{$k} = $v;
}
foreach my $k (sort keys %keys) {
    my $v = $ENV{$k} || '.';
    $v = File::Spec->rel2abs($v, $ENV{PREFIX})
        if ($v && !File::Spec->file_name_is_absolute($v)
            && grep { $k eq $_ } @subdirs);
    $ENV{$k} = $v;
}

print <<_____;
package OpenSSL::safe::installdata;

use strict;
use warnings;
use Exporter;
our \@ISA = qw(Exporter);
our \@EXPORT = qw(\$PREFIX \$BINDIR \$LIBDIR \$INCLUDEDIR \$APPLINKDIR
                  \$ENGINESDIR \$MODULESDIR \$VERSION \$LDLIBS);

our \$PREFIX     = '$ENV{PREFIX}';
our \$BINDIR     = '$ENV{BINDIR}';
our \$LIBDIR     = '$ENV{LIBDIR}';
our \$INCLUDEDIR = '$ENV{INCLUDEDIR}';
our \$ENGINESDIR = '$ENV{ENGINESDIR}';
our \$MODULESDIR = '$ENV{MODULESDIR}';
our \$APPLINKDIR = '$ENV{APPLINKDIR}';
our \$VERSION    = '$ENV{VERSION}';
our \@LDLIBS     =
    # Unix and Windows use space separation, VMS uses comma separation
    split(/ +| *, */, '$ENV{LDLIBS}');

1;
_____
