#! /usr/bin/perl

use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT top_file/;

setup("test_pkcs7");

plan tests => 3;

require_ok(top_file('test','recipes','tconversion.pl'));

subtest 'pkcs7 conversions -- pkcs7' => sub {
    tconversion("p7", top_file("test", "testp7.pem"), "pkcs7");
};
subtest 'pkcs7 conversions -- pkcs7d' => sub {
    tconversion("p7d", top_file("test", "pkcs7-1.pem"), "pkcs7");
};
