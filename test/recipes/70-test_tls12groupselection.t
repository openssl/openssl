#! /usr/bin/env perl

use OpenSSL::Test::Simple;
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils qw(alldisabled available_protocols);

setup("test_tls12groupselection");

plan skip_all => "No TLS/SSL protocols are supported by this OpenSSL build"
    if alldisabled(grep { $_ ne "ssl3" } available_protocols("tls"));

plan tests => 1;

ok(run(test(["tls12groupselection_test", srctop_file("apps", "server.pem"),
             srctop_file("apps", "server.pem")])),
   "running tls12groupselection_test");
