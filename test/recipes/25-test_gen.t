#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_gen");

plan tests => 1;

my $T = "testcert";
my $KEY = 512;
my $CA = srctop_file("certs", "testca.pem");

unlink "$T.1", "$T.2", "$T.key";
open RND, ">>", ".rnd";
print RND "string to make the random number generator think it has entropy";
close RND;

subtest "generating certificate requests" => sub {
    my @req_new;
    if (disabled("rsa")) {
	@req_new = ("-newkey", "dsa:".srctop_file("apps", "dsa512.pem"));
    } else {
	@req_new = ("-new");
	note("There should be a 2 sequences of .'s and some +'s.");
	note("There should not be more that at most 80 per line");
    }

    unlink "testkey.pem", "testreq.pem";

    plan tests => 2;

    ok(run(app(["openssl", "req", "-config", srctop_file("test", "test.cnf"),
		@req_new, "-out", "testreq.pem"])),
       "Generating request");

    ok(run(app(["openssl", "req", "-config", srctop_file("test", "test.cnf"),
		"-verify", "-in", "testreq.pem", "-noout"])),
       "Verifying signature on request");
};
