#! /usr/bin/env perl
# Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use IPC::Open2;
use OpenSSL::Test qw/:DEFAULT srctop_file bldtop_file/;
use OpenSSL::Test::Utils;

setup("test_s_apps_dtls");

plan skip_all => "test_s_apps_dtls needs sock enabled" if disabled("sock");
plan skip_all => "test_s_apps_dtls needs dtls enabled" if disabled("dtls");
plan skip_all => "test_s_apps_dtls does not run on Windows nor VMS"
    if $^O =~ /^(VMS|MSWin32|msys)$/;


my $shlib_wrap = bldtop_file("util", "shlib_wrap.sh");
my $apps_openssl = bldtop_file("apps", "openssl");
my $cert = srctop_file("apps", "server.pem");

my @test_args = (
    0,
    49152 + int(rand(65535 - 49152))
);

plan tests => 2 * ($#test_args + 1);

foreach (@test_args)
{
    run_test($_);
}

sub run_test {
    my $connect_good = 1;
    my $server_port = shift;

    my @s_cmd = ("s_server", "-accept", ":$server_port", "-cert", $cert, "-dtls", "-naccept", "1");

    my $spid = open2(my $sout, my $sin, $shlib_wrap, $apps_openssl, @s_cmd);

    # Read until we get the port
    while (<$sout>) {
        chomp;
        if ($server_port == 0 && /^ACCEPT\s.*:(\d+)$/) {
            $server_port = $1;
            last;
        } elsif (/^ACCEPT/) {
            last;
        }
    }
    print STDERR "Port: $server_port\n";
    print STDERR "Invalid port\n" if ! ok($server_port);

    # Start up the client
    my @c_cmd = ("s_client", "-connect", ":$server_port", "-dtls");

    my $cpid = open2(my $cout, my $cin, $shlib_wrap, $apps_openssl, @c_cmd);

    # Check the client output
    while (<$cout>) {
        chomp;
        $connect_good = 0 if /Cipher    : 0000/;
        last if /Session-ID:/;
    }

    # Do the "GET", which will cause the client to finish
    print $cin "Q /\r\n";
    print $sin "Q /\r\n";

    waitpid($cpid, 0);
    waitpid($spid, 0);

    print STDERR "Connection failed\n" if ! ok($connect_good);
}
