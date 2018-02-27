#! /usr/bin/perl

use strict;
use warnings;
use OpenSSL::Test qw/:DEFAULT data_file/;
use OpenSSL::Test::Utils;

setup("test_includes");

plan skip_all => "test_includes doesn't work without posix-io"
    if disabled("posix-io");

plan tests => 3;                # The number of tests being performed

ok(run(test(["conf_include_test", data_file("includes.cnf")])), "test directory includes");
ok(run(test(["conf_include_test", data_file("includes-file.cnf")])), "test file includes");
ok(run(test(["conf_include_test", data_file("includes-broken.cnf"), "f"])), "test broken includes");
