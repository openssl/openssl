#! /usr/bin/perl

use strict;
use warnings;

use OpenSSL::Test::Simple;
use OpenSSL::Test;
use OpenSSL::Test::Utils qw(alldisabled available_protocols);

setup("test_cipherlist");

my $no_anytls = alldisabled(available_protocols("tls"));

# If we have no protocols, then we also have no supported ciphers.
plan skip_all => "No SSL/TLS protocol is supported by this OpenSSL build."
    if $no_anytls;

simple_test("test_cipherlist", "cipherlist_test", "cipherlist");
