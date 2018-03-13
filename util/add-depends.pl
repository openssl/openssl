#! /usr/bin/env perl
# Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use lib '.';
use configdata;

use File::Compare qw(compare_text);

my $buildfile = $config{build_file};
my $buildfile_new = "$buildfile-$$";
my $depext = $target{dep_extension} || ".d";
my @deps =
    grep { -f $_ }
    map { (my $x = $_) =~ s|\.o$|$depext|; $x; }
    grep { $unified_info{sources}->{$_}->[0] =~ /\.cc?$/ }
    keys %{$unified_info{sources}};

open IBF, $buildfile or die "Trying to read $buildfile: $!\n";
open OBF, '>', $buildfile_new or die "Trying to write $buildfile_new: $!\n";
while (<IBF>) {
    $force_rewrite = 0;
    last if /^# DO NOT DELETE THIS LINE/;
    print OBF or die "$!\n";
    $force_rewrite = 1;
}
close IBF;

print OBF "# DO NOT DELETE THIS LINE -- make depend depends on it.\n";

foreach (@deps) {
    open IBF,$_ or die "Trying to read $_: $!\n";
    while (<IBF>) {
        print OBF or die "$!\n";
    }
    close IBF;
}
close OBF;

if (compare_text($buildfile_new, $buildfile) != 0) {
    rename $buildfile_new, $buildfile
        or die "Trying to rename $buildfile_new -> $buildfile: $!\n";
}
# On VMS, we want to remove all generations of this file, in case there are
# more than one
while (unlink $buildfile_new) {}
