#! /usr/bin/perl

use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_d2i");

plan tests => 2;

ok(run(test(["d2i_test", "x509",
             srctop_file('test','d2i-tests','bad_cert.der')])),
   "Running d2i_test bad_cert.der");

ok(run(test(["d2i_test", "generalname",
             srctop_file('test','d2i-tests','bad_generalname.der')])),
   "Running d2i_test bad_generalname.der");
