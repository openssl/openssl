#! /usr/bin/perl

use OpenSSL::Test;
use OpenSSL::Test::Utils;

setup("test_clienthello");

plan skip_all => "No TLS/SSL protocols are supported by this OpenSSL build"
    if alldisabled(grep { $_ ne "ssl3" } available_protocols("tls"));

plan tests => 1;

ok(run(test(["clienthellotest"])), "running clienthellotest");
