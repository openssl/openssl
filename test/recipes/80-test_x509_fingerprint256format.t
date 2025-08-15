#! /usr/bin/env perl
use strict;
use warnings;
use OpenSSL::Test qw/:DEFAULT/;
use OpenSSL::Test::Utils;

setup("test_x509_fingerprint256format");

plan tests => 2;

ok(run(app(["openssl", "req",
            "-x509", "-newkey", "rsa:2048",
            "-keyout", "key.pem",
            "-out", "cert.pem",
            "-days", "1", "-nodes",
            "-subj", "/CN=Test Cert"])),
   "Generate self-signed certificate");

ok(run(app(["openssl", "x509",
            "-in", "cert.pem",
            "-fingerprint256format",
            "-noout"])),
   "Print SHA-256 fingerprint in lowercase hex format");
