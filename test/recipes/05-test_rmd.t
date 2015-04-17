#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_rmd");

plan tests => 1;
ok(run(test(["rmdtest"])), "running rmdtest");
