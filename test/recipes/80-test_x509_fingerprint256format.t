#! /usr/bin/env perl

use strict;
use warnings;
use OpenSSL::Test qw(:DEFAULT srctop_file bldtop_file);
use OpenSSL::Test::Utils;
use Test::More tests => 1;

setup("test_x509_basic");

my $certfile = srctop_file("test", "certs", "servercert.pem");
my $openssl  = bldtop_file("apps", "openssl");

my $fingerprint_output = `$openssl x509 -in $certfile -noout -fingerprint256format`;
diag("Raw output:\n$fingerprint_output");

my ($fingerprint) = $fingerprint_output =~ /^([a-f0-9]{64})$/m;

my $expected = "087a6a0577bbb6eef93b0901b5a6521ce8d0e10bbc91b1575b601d91be296625";

if (!defined $fingerprint) {
    fail("Fingerprint not found in output");
} else {
    ok($fingerprint eq $expected, "Fingerprint matches expected value");
