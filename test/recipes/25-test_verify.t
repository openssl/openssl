#! /usr/bin/perl

use strict;
use warnings;

use File::Spec::Functions qw/canonpath/;
use Test::More 0.96;
use OpenSSL::Test qw/:DEFAULT top_dir top_file/;

setup("test_verify");

plan tests => 1;

note("Expect some failures and expired certificate");
ok(run(app(["openssl", "verify", "-CApath", top_dir("certs", "demo"),
	    glob(top_file("certs", "demo", "*.pem"))])), "verying demo certs");
