#! /usr/bin/perl

use OpenSSL::Test qw/:DEFAULT srctop_file srctop_dir/;
use OpenSSL::Test::Simple;

setup("test_ct");
$ENV{CTLOG_FILE} = srctop_file("test", "ct", "log_list.conf");
$ENV{CT_DIR} = srctop_dir("test", "ct");
$ENV{CERTS_DIR} = srctop_dir("test", "certs");
simple_test("test_ct", "ct_test", "ct", "ec");
