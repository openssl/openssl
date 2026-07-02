#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Spec;

my $target = shift @ARGV // die "Missing target name\n";
my $depfile = shift @ARGV // die "Missing depfile name\n";
my $makedepend = shift @ARGV // die "Missing makedepend command\n";

my $tmp = "$depfile.tmp";
my $saw_target = 0;

my $pid = open my $in, '-|';
die "Cannot fork to run $makedepend: $!\n" unless defined $pid;
if ($pid == 0) {
    open STDERR, '>', File::Spec->devnull
        or die "Cannot redirect $makedepend stderr: $!\n";
    exec $makedepend, @ARGV
        or die "Cannot run $makedepend: $!\n";
}
open my $out, '>', $tmp
    or die "Cannot open $tmp for writing: $!\n";

while (my $line = <$in>) {
    if (!$saw_target && $line =~ /^[^:]+:/) {
        $line =~ s/^[^:]+:/$target:/;
        $saw_target = 1;
    }
    print $out $line or die "Cannot write to $tmp: $!\n";
}

close $in or die "$makedepend failed\n";

if (!$saw_target) {
    print $out "$target:\n" or die "Cannot write to $tmp: $!\n";
}

close $out or die "Cannot close $tmp: $!\n";
rename $tmp, $depfile
    or die "Cannot rename $tmp to $depfile: $!\n";

END {
    unlink $tmp if defined $tmp && -e $tmp;
}
