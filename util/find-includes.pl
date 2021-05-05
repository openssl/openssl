#! /usr/bin/env perl
# Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Do a fast, not perfect but good enough, dependency list. Tries to
# avoid system header dependencies.
# Run this program like this:
#       perl ./util/err-to-raise -Iflag... files...
#       git ls-files | grep '\.c$' | perl -Iflag... ./util/err-to-raise

require 5.10.0;
use warnings;
use strict;
use File::Find;

# All header files found via -I flags.
my %headers;

# Headers that were found.
my %found_headers;

# Obvious system headers we skip.
my %skips;

# Output style; default make dependency format.
my $output = 'm';

# Directory we are scanning, removed from the pathname
my $dir = "";

sub printit {
    my ($f, $dep) = ( @_ );

    return if defined $skips{$dep};
    $found_headers{$dep} = 1;
    return if $output eq 's';

    if ( defined $headers{$dep} ) {
        print "$f : $dep\n";
    } else {
        print "# $f : $dep\n";
    }
}

sub process {
    my $f = shift;
    open(my $in, "<", $f)
        or die "Can't open $f, $!, ";

    my $dirty = 0;
    while ( <$in> ) {
        next unless /^# *include */;
        if ( m/include *"([^"]*)"/ ) {
            printit($f, $1);
            $dirty = 1;
        } elsif ( /include *<([^>]*)>/ ) {
            printit($f, $1);
            $dirty = 1;
        }
    }
    print "\n" if $dirty;

    close $in;
}

# Called by find. "Simplifies the header and updates |%headers|
sub wanted {
    return if $File::Find::name =~ m@__DECC_INCLUDE@;
    return if -d $File::Find::name;
    my $f = $File::Find::name;
    $f =~ s@^$dir@@;
    $f =~ s@\.in$@@;
    $headers{$f} = 1;
}

# Parse options.
my $arg;
options: while ( scalar @ARGV ) {
    $arg = shift @ARGV;
    last options if $arg eq '--';
    if ( $arg !~ /^-/ ) {
        unshift @ARGV, $arg;
        last options;
    }
    if ( $arg =~ /-I(.*)/ ) {
        $dir = "$1/";
        find(\&wanted, $1);
    } elsif ( $arg eq '-s' ) {
        $output = 's';
    } else {
        die "Unknown flag $arg, ";
    }
}

# Hacks.
$headers{'e_os.h'} = 1;

# Skip obvious system headers.
foreach my $s ( glob("/usr/include/*.h /usr/include/sys/*.h") ) {
    $s =~ s@/usr/include/@@;
    $skips{$s} = 1;
}


if ( scalar @ARGV ) {
    foreach my $f ( @ARGV ) {
        &process($f);
    }
} else {
    while ( <STDIN> ) {
        chomp;
        &process($_);
    }
}

if ( $output eq 's' ) {
    foreach my $f ( keys %found_headers ) {
        print $f, "\n";
    }
}
