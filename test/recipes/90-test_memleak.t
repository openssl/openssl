#! /usr/bi/nperl

use OpenSSL::Test;

setup("test_memleak");
plan tests => 1;
ok(!run(test(["memleaktest"])), "running memleaktest");
