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
use List::Util qw(pairs);

# These are expected to be set up as absolute directories
my @absolutes = qw(PREFIX libdir);
# These may be absolute directories, and if not, they are expected to be set up
# as subdirectories to PREFIX or LIBDIR.  The order of the pairs is important,
# since the LIBDIR subdirectories depend on the calculation of LIBDIR from
# PREFIX.
my @subdirs = pairs (PREFIX => [ qw(BINDIR LIBDIR INCLUDEDIR APPLINKDIR) ],
                     LIBDIR => [ qw(ENGINESDIR MODULESDIR PKGCONFIGDIR
                                    CMAKECONFIGDIR) ]);
# For completeness, other expected variables
my @others = qw(VERSION LDLIBS);

my %all = ( );
foreach (@absolutes) { $all{$_} = 1 }
foreach (@subdirs) { foreach (@{$_->[1]}) { $all{$_} = 1 } }
foreach (@others) { $all{$_} = 1 }
print STDERR "DEBUG: all keys: ", join(", ", sort keys %all), "\n";

my %keys = ();
foreach (@ARGV) {
    (my $k, my $v) = m|^([^=]*)=(.*)$|;
    $keys{$k} = 1;
    $ENV{$k} = $v;
}

# warn if there are missing values, and also if there are unexpected values
foreach my $k (sort keys %all) {
    warn "No value given for $k\n" unless $keys{$k};
}
foreach my $k (sort keys %keys) {
    warn "Unknown variable $k\n" unless $all{$k};
}

# This shouldn't be needed, but just in case we get relative paths that
# should be absolute, make sure they actually are.
foreach my $k (@absolutes) {
    my $v = $ENV{$k} || '.';
    print STDERR "DEBUG: $k = $v => ";
    $v = File::Spec->rel2abs($v) if $v;
    $ENV{$k} = $v;
    print STDERR "$k = $ENV{$k}\n";
}

# Absolute paths for the subdir variables are computed.  This provides
# the usual form of values for names that have become norm, known as GNU
# installation paths.
# For the benefit of those that need it, the subdirectories are preserved
# as they are, using the same variable names, suffixed with '_REL_{var}',
# if they are indeed subdirectories.  The '{var}' part of the name tells
# which other variable value they are relative to.
foreach my $pair (@subdirs) {
    my ($var, $subdir_vars) = @$pair;
    foreach my $k (@$subdir_vars) {
        my $v = $ENV{$k} || '.';
        print STDERR "DEBUG: $k = $v => ";
        if (File::Spec->file_name_is_absolute($v)) {
            my $kr = "${k}_REL_${var}";
            $ENV{$kr} = File::Spec->abs2rel($v, $ENV{$var});
            print STDERR "$kr = $ENV{$kr}\n";
        } else {
            my $kr = "${k}_REL_${var}";
            $ENV{$kr} = $v;
            $ENV{$k} = File::Spec->rel2abs($v, $ENV{$var});
            print STDERR "$k = $ENV{$k} ,  $kr = $v\n";
        }
    }
}

print <<_____;
package OpenSSL::safe::installdata;

use strict;
use warnings;
use Exporter;
our \@ISA = qw(Exporter);
our \@EXPORT = qw(
_____

foreach my $k (@absolutes) {
    print "    \$$k\n";
}
foreach my $pair (@subdirs) {
    my ($var, $subdir_vars) = @$pair;
    foreach my $k (@$subdir_vars) {
        my $k2 = "${k}_REL_${var}";
        print "    \$$k \$$k2\n";
    }
}

print <<_____;
    \$VERSION \@LDLIBS
);

_____

foreach my $k (@absolutes) {
    print "our \$$k" . ' ' x (27 - length($k)) . "= '$ENV{$k}';\n";
}
foreach my $pair (@subdirs) {
    my ($var, $subdir_vars) = @$pair;
    foreach my $k (@$subdir_vars) {
        my $k2 = "${k}_REL_${var}";
        print "our \$$k" . ' ' x (27 - length($k)) . "= '$ENV{$k}';\n";
        print "our \$$k2" . ' ' x (27 - length($k2)) . "= '$ENV{$k2}';\n";
    }
}

print <<_____;
our \$VERSION                    = '$ENV{VERSION}';
our \@LDLIBS                     =
    # Unix and Windows use space separation, VMS uses comma separation
    split(/ +| *, */, '$ENV{LDLIBS}');

1;
_____
