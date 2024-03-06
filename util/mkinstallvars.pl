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
my @subdirs = qw(BINDIR LIBDIR INCLUDEDIR APPLINKDIR ENGINESDIR MODULESDIR
                 PKGCONFIGDIR CMAKECONFIGDIR);

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

    # Absolute paths for the subdir variables are computed.  This provides
    # the usual form of values for names that have become norm, known as GNU
    # installation paths.
    # For the benefit of those that need it, the subdirectories are preserved
    # as they are, using the same variable names, suffixed with '_REL', if they
    # are indeed subdirectories.
    if (grep { $k eq $_ } @subdirs) {
        if (File::Spec->file_name_is_absolute($v)) {
            $ENV{"${k}_REL"} = File::Spec->abs2rel($v, $ENV{PREFIX});
        } else {
            $ENV{"${k}_REL"} = $v;
            $v = File::Spec->rel2abs($v, $ENV{PREFIX});
        }
    }
    $ENV{$k} = $v;
}

print <<_____;
package OpenSSL::safe::installdata;

use strict;
use warnings;
use Exporter;
our \@ISA = qw(Exporter);
our \@EXPORT = qw(\$PREFIX
                  \$BINDIR \$BINDIR_REL
                  \$LIBDIR \$LIBDIR_REL
                  \$INCLUDEDIR \$INCLUDEDIR_REL
                  \$APPLINKDIR \$APPLINKDIR_REL
                  \$ENGINESDIR \$ENGINESDIR_REL
                  \$MODULESDIR \$MODULESDIR_REL
                  \$PKGCONFIGDIR \$PKGCONFIGDIR_REL
                  \$CMAKECONFIGDIR \$CMAKECONFIGDIR_REL
                  \$VERSION \@LDLIBS);

our \$PREFIX             = '$ENV{PREFIX}';
our \$BINDIR             = '$ENV{BINDIR}';
our \$BINDIR_REL         = '$ENV{BINDIR_REL}';
our \$LIBDIR             = '$ENV{LIBDIR}';
our \$LIBDIR_REL         = '$ENV{LIBDIR_REL}';
our \$INCLUDEDIR         = '$ENV{INCLUDEDIR}';
our \$INCLUDEDIR_REL     = '$ENV{INCLUDEDIR_REL}';
our \$APPLINKDIR         = '$ENV{APPLINKDIR}';
our \$APPLINKDIR_REL     = '$ENV{APPLINKDIR_REL}';
our \$ENGINESDIR         = '$ENV{ENGINESDIR}';
our \$ENGINESDIR_REL     = '$ENV{ENGINESDIR_REL}';
our \$MODULESDIR         = '$ENV{MODULESDIR}';
our \$MODULESDIR_REL     = '$ENV{MODULESDIR_REL}';
our \$PKGCONFIGDIR       = '$ENV{PKGCONFIGDIR}';
our \$PKGCONFIGDIR_REL   = '$ENV{PKGCONFIGDIR_REL}';
our \$CMAKECONFIGDIR     = '$ENV{CMAKECONFIGDIR}';
our \$CMAKECONFIGDIR_REL = '$ENV{CMAKECONFIGDIR_REL}';
our \$VERSION            = '$ENV{VERSION}';
our \@LDLIBS             =
    # Unix and Windows use space separation, VMS uses comma separation
    split(/ +| *, */, '$ENV{LDLIBS}');

1;
_____
