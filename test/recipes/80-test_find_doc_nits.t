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

use OpenSSL::Test qw/:DEFAULT bldtop_dir srctop_file indir cmd run/;

setup("test_find_doc_nits");

plan tests => 2;

# Regression coverage for find-doc-nits -a including Perl test and util files.
my $script = srctop_file("util", "find-doc-nits");
open my $sfh, '<', $script or die "open $script: $!";
my $find_doc_nits_src = do { local $/; <$sfh> };
close $sfh;
ok($find_doc_nits_src =~ /push \@env_files.*\.(?:c|in|t|pl)\$/s,
   "find-doc-nits collects .t and .pl files for environment variable scan");

indir(bldtop_dir() => sub {
    my @out = run(cmd([ $^X, $script, "-a" ]), capture => 1);
    my $output = join("", @out);
    ok($output !~ /Undocumented environment variables:/,
       "find-doc-nits -a reports no undocumented environment variables");
});
