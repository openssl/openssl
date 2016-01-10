#! /usr/bi/nperl

use OpenSSL::Test;

setup("test_memleak");
plan tests => 2;
ok(run(test(["memleaktest"])), "running leak test");
ok(run(test(["memleaktest", "freeit"])), "running no leak test");
