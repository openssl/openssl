#! /usr/bin/env perl

use OpenSSL::Test::Simple;
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils qw(alldisabled available_protocols);

setup("test_tls13groupselection");

plan skip_all => "No TLS/SSL protocols are supported by this OpenSSL build"
    if alldisabled(grep { $_ ne "ssl3" } available_protocols("tls"));

plan tests => 1;

ok(run(test(["tls13groupselection_test", srctop_file("apps", "server.pem"),
             srctop_file("apps", "server.pem")])),
   "running tls13groupselection_test");
