#! /usr/bin/perl

use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_crl");

plan tests => 2;

require_ok(srctop_file('test','recipes','tconversion.pl'));

subtest 'crl conversions' => sub {
    tconversion("crl", srctop_file("test","testcrl.pem"));
};
