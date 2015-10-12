#! /usr/bin/perl

use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT top_file/;

setup("test_req");

plan tests => 3;

require_ok(top_file('test','recipes','tconversion.pl'));

my @openssl_args = ("req", "-config", "../apps/openssl.cnf");

run_conversion('req conversions',
	       "testreq.pem");
run_conversion('req conversions -- testreq2',
	       "testreq2.pem");

sub run_conversion {
    my $title = shift;
    my $reqfile = shift;

    subtest $title => sub {
	run(app(["openssl", @openssl_args,
		 "-in", $reqfile, "-inform", "p",
		 "-noout", "-text"],
		stderr => "req-check.err", stdout => undef));
	open DATA, "req-check.err";
      SKIP: {
	  plan skip_all => "skipping req conversion test for $reqfile"
	      if grep /Unknown Public Key/, map { s/\R//; } <DATA>;

	  tconversion("req", "testreq.pem", @openssl_args);
	}
	close DATA;
	unlink "req-check.err";

	done_testing();
    };
}
