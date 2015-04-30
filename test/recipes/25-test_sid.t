#! /usr/bin/perl

use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT top_file/;

setup("test_sid");

plan tests => 2;

require_ok(top_file('test','recipes','tconversion.pl'));

subtest 'sid conversions' => sub {
    tconversion("sid", top_file("test","testsid.pem"), "sess_id");
};
