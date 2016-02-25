#! /usr/bin/perl

use strict;
use warnings;
use OpenSSL::Test qw/:DEFAULT srctop_file srctop_dir with/;
use OpenSSL::Test::Utils;

setup("test_includes");

plan tests => 2;                # The number of tests being performed

#indir srctop_dir("test") => sub {
ok(run(test(["conf_include_test", srctop_file("test", "includes.cnf")])), "test includes");

with({ exit_checker => sub { return shift == 2; } },
    sub {
	ok(run(test(["conf_include_test", srctop_file("test", "includes-broken.cnf")])), "test broken includes");
    });

