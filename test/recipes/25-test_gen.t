#! /usr/bin/perl

use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT top_file/;
use OpenSSL::Test::Utils;

setup("test_gen");

plan tests => 1;

my $T = "testcert";
my $KEY = 512;
my $CA = top_file("certs", "testca.pem");

unlink "$T.1", "$T.2", "$T.key";
open RND, ">>", ".rnd";
print RND "string to make the random number generator think it has entropy";
close RND;

subtest "generating certificate requests" => sub {
    my @req_new;
    if (disabled("rsa")) {
	@req_new = ("-newkey", "dsa:".top_file("apps", "dsa512.pem"));
    } else {
	@req_new = ("-new");
	note("There should be a 2 sequences of .'s and some +'s.");
	note("There should not be more that at most 80 per line");
    }

    unlink "testkey.pem", "testreq.pem";

    plan tests => 2;

    ok(run(app(["openssl", "req", "-config", top_file("test", "test.cnf"),
		@req_new, "-out", "testreq.pem"])),
       "Generating request");

    ok(run(app(["openssl", "req", "-config", top_file("test", "test.cnf"),
		"-verify", "-in", "testreq.pem", "-noout"])),
       "Verifying signature on request");
};
