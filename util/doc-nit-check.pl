#! /usr/bin/env perl

require 5.10.0;
use warnings;
use strict;
use Pod::Checker;
use File::Find;

sub check()
{
    my $errs = 0;
    
    my $contents = '';
    {
        local $/ = undef;
        open POD, $_ or die "Couldn't open $_, $!";
        $contents = <POD>;
        close POD;
    }
    if ( $contents !~ /^=pod/ ) {
        print "$_ doesn't start with =pod\n";
        return 1;
    }
    if ( $contents !~ /=cut\n$/ ) {
        print "$_ doesn't end with =cut\n";
        return 1;
    }
    if ( $contents !~ /Copyright .* The OpenSSL Project Authors/ ) {
        print "$_ missing copyright\n";
        return 1;
    }

    $errs = podchecker($_, \*STDOUT);
    $errs = 1 if $errs < 0;
    return $errs;
}

my $errs = 0;
foreach (glob('*/*.pod')) {
    $errs += &check($_);
}
exit $errs;
