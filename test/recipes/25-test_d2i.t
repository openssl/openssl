#! /usr/bin/perl

use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_d2i");

plan tests => 1;

ok(run(test(["d2i_test", srctop_file('test','d2i-tests','bad_cert.der')])),
   "Running d2i_test bad_cert.der");
