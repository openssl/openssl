#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use IPC::Open3;
use OpenSSL::Test qw/:DEFAULT srctop_file bldtop_file/;
use OpenSSL::Test::Utils;

my $test_name = "test_stime";
setup($test_name);

plan skip_all => "$test_name is not available on $^O"
    if $^O =~ /^(VMS|MSWin32|msys)$/;
plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");
plan skip_all => "$test_name needs some TLS protocols to be enabled"
    if alldisabled(available_protocols("tls"));
plan skip_all => "$test_name needs ec, ecx or dh for TLS key exchange"
    if disabled("ec") && disabled("ecx") && disabled("dh");

my $shlib_wrap   = bldtop_file("util", "wrap.pl");
my $apps_openssl = bldtop_file("apps", "openssl");
my $server_pem   = srctop_file("apps", "server.pem");

plan tests => 4;

my @srv_cmd = ("s_server", "-accept", "0", "-cert", $server_pem);
my $srv_pid = open3(my $srv_in, my $srv_out, undef,
                    $shlib_wrap, $apps_openssl, @srv_cmd);

my $port = "0";
while (<$srv_out>) {
    chomp;
    if    (/^ACCEPT 0\.0\.0\.0:(\d+)/) { $port = $1; last; }
    elsif (/^ACCEPT \[.*\]:(\d+)/)     { $port = $1; last; }
    elsif (/^Using default/)           { ; }
    else                               { last; }
}

close $srv_out;

SKIP: {
    skip "Could not start s_server", 4 if $port eq "0";

    my $connect = "localhost:$port";

    ok(run(app(["openssl", "s_time",
                "-connect", $connect, "-new", "-testmode"])),
       "s_time new connections");
    ok(run(app(["openssl", "s_time",
                "-connect", $connect, "-reuse", "-testmode"])),
       "s_time session reuse");

    SKIP: {
        skip "TLS 1.2 disabled", 1 if disabled("tls1_2");
        ok(run(app(["openssl", "s_time",
                    "-connect", $connect, "-new", "-tls1_2", "-testmode"])),
           "s_time TLSv1.2 new connections");
    }

    SKIP: {
        skip "TLS 1.3 disabled", 1 if disabled("tls1_3");
        ok(run(app(["openssl", "s_time",
                    "-connect", $connect, "-new", "-tls1_3", "-testmode"])),
           "s_time TLSv1.3 new connections");
    }
}

close $srv_in;
kill 'HUP', $srv_pid;
waitpid($srv_pid, 0);
