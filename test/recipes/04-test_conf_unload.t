#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;
use OpenSSL::Test qw/:DEFAULT bldtop_dir bldtop_file srctop_dir/;
use OpenSSL::Test::Utils;

BEGIN { setup("test_conf_unload"); }
use lib srctop_dir('Configurations');
use lib bldtop_dir('.');
use platform;

plan skip_all => "Requires Linux pthreads and dynamic modules"
    unless config('target') =~ /^linux-/ && !disabled('threads')
        && !disabled('module') && !disabled('dso');
plan tests => 10;

my $module = bldtop_file('test', platform->dso('conf_unload_module'));
for my $point (0 .. 7) {
    ok(run(test(['conf_unload_test', 'partial', $point, $module])),
       "Partial unload allocation failure $point preserves module ownership");
}
for my $point (0, 1) {
    ok(run(test(['conf_unload_test', 'all', $point, $module])),
       "Full unload allocation failure $point");
}
