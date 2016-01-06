#!/usr/local/bin/perl -w
# Clean the dependency list in a makefile of standard includes...
# Written by Ben Laurie <ben@algroup.co.uk> 19 Jan 1999

use strict;
use Cwd;

my $path = getcwd();
$path =~ /([^\/]+)$/;
$path = $1;

while(<STDIN>) {
    print;
    last if /^# DO NOT DELETE THIS LINE/;
}

my %files;

# Fetch all the dependency output first
my $thisfile="";
while(<STDIN>) {
    my ($dummy, $file,$deps)=/^((.*):)? (.*)$/;
    $thisfile=$file if defined $file;
    next if !defined $deps;
    my @deps=split ' ',$deps;
    @deps=grep(!/^\\$/,@deps);
    push @{$files{$thisfile}},@deps;
}

my $file;

# Time to clean out possible system directories and normalise quirks
# from different makedepend methods
foreach $file (sort keys %files) {
    # This gets around a quirk with gcc, which removes all directory
    # information from the original file
    my $tmpfile=$file;
    $tmpfile=~s/\.o$/.c/;
    (my $origfile)=grep(/(^|\/)${tmpfile}$/,@{$files{$file}});
    my $newfile=$origfile;
    $newfile=~s/\.c$/.o/;
    if ($newfile ne $file) {
        $files{$newfile} = $files{$file};
        delete $files{$file};
        $file = $newfile;
    }

    @{$files{$file}} =
        grep(!/^\//,
             grep(!/^$origfile$/, @{$files{$file}}));
}

foreach $file (sort keys %files) {
    my $len=0;
    my $dep;
    my $origfile=$file;
    $origfile=~s/\.o$/.c/;
    $file=~s/^\.\///;
    push @{$files{$file}},$origfile;
    my $prevdep="";

    # Remove leading ./ before sorting
    my @deps = map { $_ =~ s/^\.\///; $_ } @{$files{$file}};
    # Remove ../thisdir/
    @deps = map { $_ =~ s|^../$path/||; $_ } @deps;

    foreach $dep (sort @deps) {
	$dep=~s/^\.\///;
	next if $prevdep eq $dep; # to exterminate duplicates...
	$prevdep = $dep;
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
