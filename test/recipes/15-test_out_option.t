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
    '/',
    './',
    '../'
   );
my @success_paths = (
    'test.pem'
   );

# /usr/ can only be expected on Unix lookalikes...  On Windows and VMS,
# this might be a writable file, so let's not bother those platforms
# with it.
push @failure_paths, '/usr/'
    unless $^O eq 'MSWin32' ||  $^O eq 'VMS';

# Test for trying to create a file in a non-exist directory
my $rand_path = "";
do {
    my @chars = ("A".."Z", "a".."z", "0".."9");
    $rand_path .= $chars[rand @chars] for 1..32;
} while (-d File::Spec->catdir('.', $rand_path));
$rand_path .= "/test.pem";

push @failure_paths, $rand_path;

# Specifically for mingw, the NULL device might not be what's expected.
# For example, if cross compiled and tested on the build host, perl will
# generate an incorrect NULL device name.
# We might expand the exceptions...
unless (config('target') =~ m|^mingw| && $^O ne 'msys') {
    # Check that we can write to the NULL device
    push @success_paths, File::Spec->devnull();
}

# chmod doesn't seem to work as expected in Windows Command prompt,
# so these test are meaningless in that environment (for example,
# "unwritable.pem" turns out to be writable...
unless ($^O eq 'MSWin32') {
    # Check that we can write to a file that we have write permission to
    # in a directory that we don't have write permission to.
    my $tempdir = File::Spec->catdir('.', "test_out_option-nowrite-$$");
    mkdir $tempdir or die "Trying to create $tempdir: $!\n";
    my $tempfile = File::Spec->catfile($tempdir, "writable.pem");
    open my $fh, ">", $tempfile or die "Trying to create $tempfile: $!\n";
    chmod 0555, $tempdir;
    push @success_paths, $tempfile;

    # Check that non-existent files cannot be created in a directory that
    # we don't have write permission to.
    push @failure_paths, File::Spec->catfile($tempdir, "unwritable.pem");
}

plan tests => (2 * scalar @failure_paths) + scalar @success_paths;

test_illegal_path($_) foreach @failure_paths;
test_legal_path($_) foreach @success_paths;

END {
    if (-d $tempdir) {
        chmod 0755, $tempdir;
        unlink $tempfile if -f $tempfile;
        rmdir $tempdir;
    }
    unlink 'test.pem' if -f 'test.pem';
}

sub test_illegal_path {
    my $path = File::Spec->canonpath($_[0]);

    my $start = time();
    ok(!run(app([ 'openssl', 'genrsa', '-out', $path, '16384'])), "invalid output path: $path");
    my $end = time();
    # The above process should exit in 2 seconds if the path is not valid
    ok($end - $start < 2, "check time consumed");
}

sub test_legal_path {
    my $path = File::Spec->canonpath($_[0]);

    ok(run(app([ 'openssl', 'genrsa', '-out', $path, '2048'])), "valid output path: $path");
}
