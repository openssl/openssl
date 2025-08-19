#! /usr/bin/env perl
use strict;
use warnings;
use OpenSSL::Test qw/:DEFAULT/;
use OpenSSL::Test::Utils;

setup("test_x509_fingerprint256format");

plan tests => 1;

ok(run(app(["openssl", "x509",
            "-in", "certs/servercert.pem",
            "-fingerprint256format",
            "-noout"])),
   "Print SHA-256 fingerprint in lowercase hex format");
