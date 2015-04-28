#! /usr/bin/perl

use strict;
use warnings;

use POSIX;
use File::Spec::Functions qw/splitdir curdir catfile/;
use File::Compare;
use Test::More 0.96;
use OpenSSL::Test qw/:DEFAULT cmdstr top_file/;

setup("test_tsa");

# All these are modified inside indir further down. They need to exist
# here, however, to be available in all subroutines.
my $testtsa;
my $CAtsa;

sub create_ca {
    $ENV{TSDNSECT} = "ts_ca_dn";
    return
	ok(run(app(["openssl", "req", "-new", "-x509", "-nodes",
		    "-out", "tsaca.pem", "-keyout", "tsacakey.pem"])),
	   'creating a new CA for the TSA tests');
}

sub create_tsa_cert {
    my $INDEX = shift;
    my $EXT = shift;
    my $r = 1;
    $ENV{TSDNSECT} = "ts_ca_dn";

    $r *= ok(run(app(["openssl", "req", "-new",
		      "-out", "tsa_req${INDEX}.pem",
		      "-keyout", "tsa_key${INDEX}.pem"])));
    note "using extension $EXT";
    $r *= ok(run(app(["openssl", "x509", "-req",
		      "-in", "tsa_req${INDEX}.pem",
		      "-out", "tsa_cert${INDEX}.pem",
		      "-CA", "tsaca.pem", "-CAkey", "tsacakey.pem",
		      "-CAcreateserial",
		      "-extfile", $ENV{OPENSSL_CONF}, "-extensions", $EXT])));
    return $r;
}

sub print_request {
    my $input = shift;
    return ok(run(app(["openssl", "ts", "-query", "-in", $input, "-text"])));
}

sub create_time_stamp_request1 {
    return
	ok(run(app(["openssl", "ts", "-query", "-data", $testtsa, "-policy", "tsa_policy1", "-cert", "-out", "req1.tsq"])));
}

sub create_time_stamp_request2 {

    return
	ok(run(app(["openssl", "ts", "-query", "-data", $testtsa, "-policy", "tsa_policy2", "-no_nonce", "-out", "req2.tsq"])));
}

sub create_time_stamp_request3 {

    return
	ok(run(app(["openssl", "ts", "-query", "-data", $CAtsa, "-no_nonce", "-out", "req3.tsq"])))
}

sub print_response {
    my $inputfile = shift;

    return
	ok(run(app(["openssl", "ts", "-reply", "-in", "$inputfile", "-text"])));
}

sub create_time_stamp_response {
    my $queryfile = shift;
    my $outputfile = shift;
    my $datafile = shift;

    return
	ok(run(app(["openssl", "ts", "-reply", "-section", "$datafile", "-queryfile", "$queryfile", "-out", "$outputfile"])));
}

sub time_stamp_response_token_test {
    my $queryfile = shift;
    my $inputfile = shift;
    my $RESPONSE2="$inputfile.copy.tsr";
    my $TOKEN_DER="$inputfile.token.der";

    ok(run(app(["openssl", "ts", "-reply", "-in", "$inputfile", "-out", "$TOKEN_DER", "-token_out"])));
    ok(run(app(["openssl", "ts", "-reply", "-in", "$TOKEN_DER", "-token_in", "-out", "$RESPONSE2"])));
    is(compare($RESPONSE2, $inputfile), 0);
    ok(run(app(["openssl", "ts", "-reply", "-in", "$inputfile", "-text", "-token_out"])));
    ok(run(app(["openssl", "ts", "-reply", "-in", "$TOKEN_DER", "-token_in", "-text", "-token_out"])));
    ok(run(app(["openssl", "ts", "-reply", "-queryfile", "$queryfile", "-text", "-token_out"])));
}

sub verify_time_stamp_response {
    my $queryfile = shift;
    my $inputfile = shift;
    my $datafile = shift;

    ok(run(app(["openssl", "ts", "-verify", "-queryfile", "$queryfile", "-in", "$inputfile", "-CAfile", "tsaca.pem", "-untrusted", "tsa_cert1.pem"])));
    ok(run(app(["openssl", "ts", "-verify", "-data", "$datafile", "-in", "$inputfile", "-CAfile", "tsaca.pem", "-untrusted", "tsa_cert1.pem"])));
}

sub verify_time_stamp_token {
    my $queryfile = shift;
    my $inputfile = shift;
    my $datafile = shift;

    # create the token from the response first
    ok(run(app(["openssl", "ts", "-reply", "-in", "$inputfile", "-out", "$inputfile.token", "-token_out"])));
    ok(run(app(["openssl", "ts", "-verify", "-queryfile", "$queryfile", "-in", "$inputfile.token", "-token_in", "-CAfile", "tsaca.pem", "-untrusted", "tsa_cert1.pem"])));
    ok(run(app(["openssl", "ts", "-verify", "-data", "$datafile", "-in", "$inputfile.token", "-token_in", "-CAfile", "tsaca.pem", "-untrusted", "tsa_cert1.pem"])));
}

sub verify_time_stamp_response_fail {
    my $queryfile = shift;
    my $inputfile = shift;

    ok(!run(app(["openssl", "ts", "-verify", "-queryfile", "$queryfile", "-in", "$inputfile", "-CAfile", "tsaca.pem", "-untrusted", "tsa_cert1.pem"])));
}

# main functions

indir "tsa" => sub {

    $ENV{OPENSSL_CONF} = top_file("test", "CAtsa.cnf");
    # Because that's what ../apps/CA.pl really looks at
    $ENV{SSLEAY_CONFIG} = "-config ".$ENV{OPENSSL_CONF};
    $ENV{OPENSSL} = cmdstr(app(["openssl"]));
    $testtsa = top_file("test", "recipes", "80-test_tsa.t");
    $CAtsa = top_file("test", "CAtsa.cnf");

    plan tests => 20;

  SKIP: {
      skip "failed", 19
	  if !subtest 'creating CA for TSA tests' => sub { create_ca };

      skip "failed", 18
	  if !subtest 'creating tsa_cert1.pem TSA server cert' => sub {
	      create_tsa_cert("1", "tsa_cert")
      };

      skip "failed", 17
	  if !subtest 'creating tsa_cert2.pem non-TSA server cert' => sub {
	      create_tsa_cert("2", "non_tsa_cert")
      };

      skip "failed", 16
	  if !subtest 'creating req1.req time stamp request for file testtsa' => sub {
	      create_time_stamp_request1()
      };

      subtest 'printing req1.req' => sub {
	  print_request("req1.tsq")
      };

      subtest 'generating valid response for req1.req' => sub {
	  create_time_stamp_response("req1.tsq", "resp1.tsr", "tsa_config1")
      };

      subtest 'printing response' => sub {
	  print_response("resp1.tsr")
      };

      subtest 'verifying valid response' => sub {
	  verify_time_stamp_response("req1.tsq", "resp1.tsr", $testtsa)
      };

      subtest 'verifying valid token' => sub {
	  verify_time_stamp_token("req1.tsq", "resp1.tsr", $testtsa)
      };

      subtest 'creating req2.req time stamp request for file testtsa' => sub {
	  create_time_stamp_request2()
      };

      subtest 'printing req2.req' => sub {
	  print_request("req2.tsq")
      };

      subtest 'generating valid response for req2.req' => sub {
	  create_time_stamp_response("req2.tsq", "resp2.tsr", "tsa_config1")
      };

      subtest 'checking -token_in and -token_out options with -reply' => sub {
	  time_stamp_response_token_test("req2.tsq", "resp2.tsr")
      };

      subtest 'printing response' => sub {
	  print_response("resp2.tsr")
      };

      subtest 'verifying valid response' => sub {
	  verify_time_stamp_response("req2.tsq", "resp2.tsr", $testtsa)
      };

      subtest 'verifying response against wrong request, it should fail' => sub {
	  verify_time_stamp_response_fail("req1.tsq", "resp2.tsr")
      };

      subtest 'verifying response against wrong request, it should fail' => sub {
	  verify_time_stamp_response_fail("req2.tsq", "resp1.tsr")
      };

      subtest 'creating req3.req time stamp request for file CAtsa.cnf' => sub {
	  create_time_stamp_request3()
      };

      subtest 'printing req3.req' => sub {
	  print_request("req3.tsq")
      };

      subtest 'verifying response against wrong request, it should fail' => sub {
	  verify_time_stamp_response_fail("req3.tsq", "resp1.tsr")
      };
    }
}, cleanup => 1, create => 1;
