#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Temp qw(tempdir);
use IPC::Open2;
use OpenSSL::Test qw/:DEFAULT bldtop_file srctop_file/;
use OpenSSL::Test::Utils;
use Socket ();

setup("test_app_s_server");

plan skip_all => "test_app_s_server needs sockets"
    if disabled("sock");
plan skip_all => "test_app_s_server needs TLS 1.2 or TLS 1.3"
    if alldisabled("tls1_2", "tls1_3");
plan skip_all => "test_app_s_server is not available on $^O"
    if $^O =~ /^(VMS|MSWin32|msys)$/;

plan tests => 3;

my @openssl = (bldtop_file("util", "wrap.pl"), bldtop_file("apps", "openssl"));
my $cert = srctop_file("test", "certs", "servercert.pem");
my $key = srctop_file("test", "certs", "serverkey.pem");

sub test_listener {
    my ($listen_option, $listen_address, $accept_pattern) = @_;
    my ($server_pid, $client_pid);

    my $ok = eval {
        local $SIG{ALRM} = sub { die "s_server or s_client timed out\n" };
        local $SIG{PIPE} = "IGNORE";
        alarm(30);

        $server_pid = open2(my $server_out, my $server_in, @openssl, "s_server",
                            $listen_option, $listen_address,
                            "-cert", $cert, "-key", $key,
                            "-www", "-naccept", "1");

        my $line;
        while (defined($line = <$server_out>)) {
            chomp $line;
            last if $line =~ /^ACCEPT/;
        }
        die "s_server exited before announcing its listener\n"
            unless defined $line;

        die "unexpected listener announcement: '$line'\n"
            unless $line =~ $accept_pattern;
        my @connect = $listen_option eq "-unix" ? ("-unix", $listen_address)
                                                : ("-connect", $1);

        $client_pid = open2(my $client_out, my $client_in, @openssl, "s_client",
                            @connect, "-quiet");
        print {$client_in} "GET / HTTP/1.0\r\n\r\n";
        close($client_in) or die "could not send HTTP request: $!\n";
        my $response = do { local $/; <$client_out> };
        waitpid($client_pid, 0);
        undef $client_pid;
        die "s_client failed (status $?)\n" if $? != 0;
        die "no HTTP 200 response from s_server\n"
            unless defined($response) && $response =~ m{\AHTTP/1\.0 200\b};

        waitpid($server_pid, 0);
        undef $server_pid;
        die "s_server failed (status $?)\n" if $? != 0;
        1;
    };
    my $error = $@;
    alarm(0);
    for my $pid (grep { defined } ($client_pid, $server_pid)) {
        kill "KILL", $pid;
        waitpid($pid, 0);
    }
    diag($error) unless $ok;
    return $ok;
}

SKIP: {
    skip "Unix-domain sockets unavailable", 1
        unless eval { socket(my $sock, Socket::AF_UNIX(), Socket::SOCK_STREAM(), 0) };
    # Keep the socket path relative to avoid the sockaddr_un length limit.
    my $dir = tempdir("unix-XXXXXX", DIR => ".", CLEANUP => 1);
    ok(test_listener("-unix", "$dir/tls.sock", qr/^ACCEPT$/),
       "Unix listener prints ACCEPT and serves TLS");
}

SKIP: {
    skip "IPv4 unavailable", 1 unless have_IPv4();
    ok(test_listener("-accept", "127.0.0.1:0",
                     qr/^ACCEPT (127\.0\.0\.1:[1-9][0-9]*)$/),
       "IPv4 listener reports its assigned port and serves TLS");
}

SKIP: {
    skip "IPv6 unavailable", 1 unless have_IPv6();
    ok(test_listener("-accept", "[::1]:0",
                     qr/^ACCEPT (\[::1\]:[1-9][0-9]*)$/),
       "IPv6 listener reports its assigned port and serves TLS");
}
