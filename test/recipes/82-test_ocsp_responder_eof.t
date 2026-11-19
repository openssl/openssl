#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Check that the "openssl ocsp" responder keeps serving requests after a
# client connects and closes the connection without sending any request.

use strict;
use warnings;

use IO::Socket::IP;
use IPC::Open3;
use OpenSSL::Test qw/:DEFAULT srctop_file bldtop_file/;
use OpenSSL::Test::Utils;
use Symbol 'gensym';

my $test_name = "test_ocsp_responder_eof";
setup($test_name);

plan skip_all => "$test_name requires OCSP support"
    if disabled("ocsp");
plan skip_all => "$test_name requires EC cryptography"
    if disabled("ec");
plan skip_all => "$test_name requires sock enabled"
    if disabled("sock");
plan skip_all => "$test_name is not available Windows or VMS"
    if $^O =~ /^(VMS|MSWin32|msys)$/;

plan tests => 3;

my $shlib_wrap   = bldtop_file("util", "shlib_wrap.sh");
my $apps_openssl = bldtop_file("apps", "openssl");

my $index_txt = srctop_file("test", "ocsp-tests", "index.txt");
my $ocsp_pem  = srctop_file("test", "ocsp-tests", "ocsp.pem");
my $ca_pem    = srctop_file("test", "ocsp-tests", "intermediate-cert.pem");
my $cert_pem  = srctop_file("test", "ocsp-tests", "server.pem");

# Serve a single real request, then exit.
my @ocsp_cmd = ("ocsp", "-port", "0", "-nrequest", "1", "-index", $index_txt,
                "-rsigner", $ocsp_pem, "-CA", $ca_pem);
my $ocsp_pid = open3(my $ocsp_i, my $ocsp_o, my $ocsp_e = gensym,
                     $shlib_wrap, $apps_openssl, @ocsp_cmd);

my $port = "0";
while (<$ocsp_o>) {
    print($_);
    if (/^ACCEPT (?:0\.0\.0\.0|\[::\]):(\d+)/) {
        $port = $1;
    }
    last;
}
ok($port ne "0", "ocsp responder port check");

SKIP: {
    skip "ocsp responder did not start", 2 if $port eq "0";

    # Connect and close again without sending any request bytes.
    my $sock = IO::Socket::IP->new(PeerHost => "localhost",
                                   PeerPort => $port,
                                   Proto => "tcp");
    ok(defined $sock, "idle client connected");
    close($sock) if defined $sock;

    # The responder must still answer the next client.
    ok(run(app(["openssl", "ocsp", "-issuer", $ca_pem, "-cert", $cert_pem,
                "-url", "http://localhost:$port/", "-timeout", "10",
                "-noverify"])),
       "ocsp responder answers request after idle connection closed");
}

kill("TERM", $ocsp_pid);
waitpid($ocsp_pid, 0);
