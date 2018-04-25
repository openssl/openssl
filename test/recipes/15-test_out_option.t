#! /usr/bin/env perl
# Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_out_option");

# Paths that should generate failure when trying to write to them.
# Directories are a safe bet for failure on all platforms.
# Note that directories must end with a slash here, because of how
# File::Spec massages them into directory specs on some platforms.
my @failure_paths = (
    './',
   );
my @success_paths = (
    'randomname.bin'
   );

# Test for trying to create a file in a non-exist directory
my $rand_path = "";
do {
    my @chars = ("A".."Z", "a".."z", "0".."9");
    $rand_path .= $chars[rand @chars] for 1..32;
} while (-d File::Spec->catdir('.', $rand_path));
$rand_path .= "/randomname.bin";

push @failure_paths, $rand_path;

# All explicit cross compilations run a risk of failing this, because the
# null device provided by perl might not match what the cross compiled
# application expects to see as a null device.  Therefore, we skip the check
# of outputing to the null device if the cross compile prefix is set.
if ((config('CROSS_COMPILE') // '') eq '') {
    # Check that we can write to the NULL device
    push @success_paths, File::Spec->devnull();
}

plan tests => scalar @failure_paths + scalar @success_paths;

foreach (@failure_paths) {
    my $path = File::Spec->canonpath($_);
    ok(!run(app([ 'openssl', 'rand', '-out', $path, '1'])),
       "invalid output path: $path");
}
foreach (@success_paths) {
    my $path = File::Spec->canonpath($_);
    ok(run(app([ 'openssl', 'rand', '-out', $path, '1'])),
       "valid output path: $path");
}

END {
    unlink 'randomname.bin' if -f 'randomname.bin';
}
