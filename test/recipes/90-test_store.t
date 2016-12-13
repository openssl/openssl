#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test qw(:DEFAULT srctop_file bldtop_file);

my $test_name = "test_store";
setup($test_name);

plan tests => 9;

indir "store_$$" => sub
{
 SKIP:
    {
	skip "failed initialisation", 9
	    unless (run(app(["openssl", "x509",
			     "-in", srctop_file("test", "testx509.pem"),
			     "-out", "testx509.der", "-outform", "der"]))
		    && run(app(["openssl", "rsa",
				"-in", srctop_file("test", "testrsa.pem"),
				"-out", "testrsa.der", "-outform", "der"]))
		    && run(app(["openssl", "rsa", "-pubin",
				"-in", srctop_file("test", "testrsapub.pem"),
				"-out", "testrsapub.der", "-outform", "der"]))
		    && run(app(["openssl", "crl",
				"-in", srctop_file("test", "testcrl.pem"),
				"-out", "testcrl.der", "-outform", "der"])));

	ok(run(app(["openssl", "storeutl", srctop_file("test", "testx509.pem")])));
	ok(run(app(["openssl", "storeutl", "testx509.der"])));
	ok(run(app(["openssl", "storeutl", srctop_file("test", "testrsa.pem")])));
	ok(run(app(["openssl", "storeutl", "testrsa.der"])));
	ok(run(app(["openssl", "storeutl", srctop_file("test", "testrsapub.pem")])));
	ok(run(app(["openssl", "storeutl", "testrsapub.der"])));
	ok(run(app(["openssl", "storeutl", srctop_file("test", "testcrl.pem")])));
	ok(run(app(["openssl", "storeutl", "testcrl.der"])));
	ok(run(app(["openssl", "storeutl", srctop_file("apps", "server.pem")])));
    }
}, create => 1, cleanup => 1;
