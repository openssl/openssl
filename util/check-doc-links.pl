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
use File::Basename;

# Collection of links in each POD file.
# filename => [ "foo(1)", "bar(3)", ... ]
my %link_collection = ();
# Collection of names in each POD file.
# "name(s)" => filename
my %name_collection = ();

sub collect {
    my $filename = shift;
    $filename =~ m|man(\d)/|;
    my $section = $1;
    my $simplename = basename($filename, ".pod");
    my $err = 0;

    my $contents = '';
    {
        local $/ = undef;
        open POD, $filename or die "Couldn't open $filename, $!";
        $contents = <POD>;
        close POD;
    }

    $contents =~ /=head1 NAME([^=]*)=head1 /ms;
    my $tmp = $1;
    unless (defined $tmp) {
        warn "weird name section in $filename\n";
        return 1;
    }
    $tmp =~ tr/\n/ /;
    $tmp =~ s/-.*//g;

    my @names = map { s/\s+//g; $_ } split(/,/, $tmp);
    unless (grep { $simplename eq $_ } @names) {
        warn "$simplename missing among the names in $filename\n";
        push @names, $simplename;
    }
    foreach my $name (@names) {
        next if $name eq "";
        my $namesection = "$name($section)";
        if (exists $name_collection{$namesection}) {
            warn "$namesection, found in $filename, already exists in $name_collection{$namesection}\n";
            $err++;
        } else {
            $name_collection{$namesection} = $filename;
        }
    }

    my @foreign_names =
        map { map { s/\s+//g; $_ } split(/,/, $_) }
        $contents =~ /=for\s+comment\s+foreign\s+manuals:\s*(.*)\n\n/;
    foreach (@foreign_names) {
        $name_collection{$_} = undef; # It still exists!
    }

    my @links = $contents =~ /L<
                              # if the link is of the form L<something|name(s)>,
                              # then remove 'something'.  Note that 'something'
                              # may contain POD codes as well...
                              (?:(?:[^\|]|<[^>]*>)*\|)?
                              # we're only interested in referenses that have
                              # a one digit section number
                              ([^\/>\(]+\(\d\))
                             /gx;
    $link_collection{$filename} = [ @links ];

    return $err;
}

sub check {
    foreach my $filename (sort keys %link_collection) {
        foreach my $link (@{$link_collection{$filename}}) {
            warn "$link in $filename refers to a non-existing manual\n"
                unless exists $name_collection{$link};
        }
    }
}


my $errs = 0;
foreach (@ARGV ? @ARGV : glob('doc/*/*.pod')) {
    $errs += collect($_);
}
check() unless $errs > 0;

exit;
