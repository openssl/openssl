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

my $temp = '/tmp/docnits.txt';
my $OUT;

sub check()
{
    my $contents = '';
    {
        local $/ = undef;
        open POD, $_ or die "Couldn't open $_, $!";
        $contents = <POD>;
        close POD;
    }
    print $OUT "$_ doesn't start with =pod\n"
        if $contents !~ /^=pod/;
    print $OUT "$_ doesn't end with =cut\n"
        if $contents !~ /=cut\n$/;
    print $OUT "$_ more than one cut line.\n"
        if $contents =~ /=cut.*=cut/ms;
    print $OUT "$_ missing copyright\n"
        if $contents !~ /Copyright .* The OpenSSL Project Authors/;
    print $OUT "$_ copyright not last\n"
        if $contents =~ /head1 COPYRIGHT.*=head/ms;
    print $OUT "$_ head2 in All uppercase\n"
        if $contents =~ /head2.*[A-Z ]+\n/;

    podchecker($_, $OUT);
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
