#!/usr/local/bin/perl -w
# Clean the dependency list in a makefile of standard includes...
# Written by Ben Laurie <ben@algroup.co.uk> 19 Jan 1999

use strict;

while(<STDIN>) {
    print;
    last if /^# DO NOT DELETE THIS LINE/;
}

my %files;

while(<STDIN>) {
    my ($file,$deps)=/^(.*): (.*)$/;
    next if !defined $deps;
    my @deps=split ' ',$deps;
    @deps=grep(!/^\/usr\/include/,@deps);
    @deps=grep(!/^\/usr\/lib\/gcc-lib/,@deps);
    push @{$files{$file}},@deps;
}

my $file;
foreach $file (sort keys %files) {
    my $len=0;
    my $dep;
    foreach $dep (sort @{$files{$file}}) {
	$len=0 if $len+length($dep)+1 >= 80;
	if($len == 0) {
	    print "\n$file:";
	    $len=length($file)+1;
	}
	print " $dep";
	$len+=length($dep)+1;
    }
}

print "\n";
