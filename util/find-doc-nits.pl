#! /usr/bin/env perl
# Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


require 5.10.0;
use warnings;
use strict;
use Pod::Checker;
use File::Find;
use File::Basename;

my $temp = '/tmp/docnits.txt';
my $OUT;

my %mandatory_sections =
    ( '*'    => [ 'NAME', 'DESCRIPTION', 'COPYRIGHT' ],
      1      => [ 'SYNOPSIS', '(COMMAND\s+)?OPTIONS' ],
      3      => [ 'SYNOPSIS', 'RETURN\s+VALUES' ],
      5      => [ ],
      7      => [ ] );
my %default_sections =
    ( apps   => 1,
      crypto => 3,
      ssl    => 3 );

sub check()
{
    my $filename = shift;
    my $dirname = basename(dirname($filename));

    my $contents = '';
    {
        local $/ = undef;
        open POD, $filename or die "Couldn't open $filename, $!";
        $contents = <POD>;
        close POD;
    }

    my $id = "${filename}:1:";
    print $OUT "$id doesn't start with =pod\n"
        if $contents !~ /^=pod/;
    print $OUT "$id doesn't end with =cut\n"
        if $contents !~ /=cut\n$/;
    print $OUT "$id more than one cut line.\n"
        if $contents =~ /=cut.*=cut/ms;
    print $OUT "$id missing copyright\n"
        if $contents !~ /Copyright .* The OpenSSL Project Authors/;
    print $OUT "$id copyright not last\n"
        if $contents =~ /head1 COPYRIGHT.*=head/ms;
    print $OUT "$id head2 in All uppercase\n"
        if $contents =~ /head2\s+[A-Z ]+\n/;
    print $OUT "$id period in NAME section\n"
        if $contents =~ /NAME.*\.\n.*SYNOPSIS/ms;
    print $OUT "$id POD markup in NAME section\n"
        if $contents =~ /NAME.*[<>].*SYNOPSIS/ms;

    # Look for multiple consecutive openssl #include lines.
    # Consecutive because of files like md5.pod. Sometimes it's okay
    # or necessary, as in ssl/SSL_set1_host.pod
    if ( $contents !~ /=for comment multiple includes/ ) {
        if ( $contents =~ /=head1 SYNOPSIS(.*)=head1 DESCRIPTION/ms ) {
            my $count = 0;
            foreach my $line ( split /\n+/, $1 ) {
                if ( $line =~ m@include <openssl/@ ) {
                    if ( ++$count == 2 ) {
                        print $OUT "$id has multiple includes\n";
                    }
                } else {
                    $count = 0;
                }
            }
        }
    }

    # Find what section this page is in.  If run from "." assume
    # section 3.
    my $section = $default_sections{$dirname} || 3;
    if ($contents =~ /^=for\s+comment\s+openssl_manual_section:\s*(\d+)\s*$/m) {
        $section = $1;
    }

    foreach ((@{$mandatory_sections{'*'}}, @{$mandatory_sections{$section}})) {
        print $OUT "$id doesn't have a head1 section matching $_\n"
            if $contents !~ /^=head1\s+${_}\s*$/m;
    }

    podchecker($filename, $OUT);
}

open $OUT, '>', $temp
    or die "Can't open $temp, $!";
foreach (@ARGV ? @ARGV : glob('*/*.pod')) {
    &check($_);
}
close $OUT;

my $count = 0;
open $OUT, '<', $temp
    or die "Can't read $temp, $!";
while ( <$OUT> ) {
    next if /\(section\) in.*deprecated/;
    $count++;
    print;
}
close $OUT;
unlink $temp || warn "Can't remove $temp, $!";

exit $count;
