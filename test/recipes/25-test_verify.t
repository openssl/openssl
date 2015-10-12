#! /usr/bin/perl

use strict;
use warnings;

use File::Spec::Functions qw/canonpath/;
use OpenSSL::Test qw/:DEFAULT top_dir top_file/;

setup("test_verify");

plan skip_all => "no rehash.time was found."
    unless (-f top_file("rehash.time"));

plan tests => 1;

note("Expect some failures and expired certificate");
ok(run(app(["openssl", "verify", "-CApath", top_dir("certs", "demo"),
	    glob(top_file("certs", "demo", "*.pem"))])), "verying demo certs");
