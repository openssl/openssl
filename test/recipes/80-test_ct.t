#! /usr/bin/perl

use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Simple;

setup("test_ct");
$ENV{CTLOG_FILE} = srctop_file("test", "ct", "log_list.conf");
simple_test("test_ct", "ct_test", "ct");

