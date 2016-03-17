#! /usr/bin/perl

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_ssl_test_ctx");

plan tests => 1;
ok(run(test(["ssl_test_ctx_test", srctop_file("test", "ssl_test_ctx_test.conf")])),
   "running ssl_test_ctx_test ssl_test_ctx_test.conf");
