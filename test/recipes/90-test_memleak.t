#! /usr/bi/nperl

use OpenSSL::Test;

setup("memleaktest");
plan tests => 1;
ok(!run(test(["memleaktest"])), "running memleaktest");
