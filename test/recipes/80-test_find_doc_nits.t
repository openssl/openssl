#! /usr/bin/env perl
#
# Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Spec::Functions qw(rel2abs);
use OpenSSL::Test qw/:DEFAULT bldtop_dir bldtop_file srctop_file indir cmd run/;

setup("test_find_doc_nits");

plan tests => 4;

# srctop_file() returns a path relative to the recipe's start directory, but
# the last test runs the script from the build top, so make it absolute here.
my $script = rel2abs(srctop_file("util", "find-doc-nits"));
open my $sfh, '<', $script or die "open $script: $!";
my $find_doc_nits_src = do { local $/; <$sfh> };
close $sfh;

ok($find_doc_nits_src =~ /push \@env_files.*\Q\.(?:c|in|t|pl)\E\$/s,
   "find-doc-nits collects .t and .pl files for environment variable scan");

ok($find_doc_nits_src =~ /env-ignore\.txt/
   && $find_doc_nits_src =~ /missingenv\.txt/,
   "find-doc-nits loads env-var ignore lists from external files");

ok(-f srctop_file("util", "env-ignore.txt")
   && -f srctop_file("util", "missingenv.txt"),
   "external env-var list files exist in util/");

# find-doc-nits reads every manual page, including the ones generated from
# .pod.in files, which "make test" does not build.  openssl-ca.pod is one of
# them and stands in for the whole set.
my $have_generated_pods = -f bldtop_file("doc", "man1", "openssl-ca.pod");

SKIP: {
    skip "generated pods are not built, run 'make build_generated_pods'", 1
        unless $have_generated_pods;

    indir(bldtop_dir() => sub {
        my $status = 0;
        my @out = run(cmd([ $^X, $script, "-a" ]), capture => 1,
                      statusvar => \$status);
        my $output = join("", @out);
        ok($status && $output !~ /Undocumented environment variables:/,
           "find-doc-nits -a reports no undocumented environment variables")
            or diag($output);
    });
}
