#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# Regression test for GH #30458: s_client -reconnect must free the socket BIO
# when reconnecting to avoid a memory leak (detected by LeakSanitizer).

use strict;
use warnings;

use IPC::Open3;
use OpenSSL::Test qw/:DEFAULT srctop_file bldtop_file/;
use OpenSSL::Test::Utils;
use Symbol 'gensym';

my $test_name = "test_s_client_reconnect";
setup($test_name);

plan skip_all => "$test_name requires sock enabled"
    if disabled("sock");
plan skip_all => "$test_name requires TLS enabled"
    if alldisabled(available_protocols("tls"));
plan skip_all => "$test_name requires TLS 1.2 (test uses -tls1_2 for broad build compatibility)"
    if disabled("tls1_2");
plan skip_all => "$test_name is not available on Windows or VMS"
    if $^O =~ /^(VMS|MSWin32|msys)$/;

plan tests => 3;

# Ignore SIGPIPE so writes to server/client pipes do not kill us if the child has exited
$SIG{PIPE} = 'IGNORE';

my $shlib_wrap   = bldtop_file("util", "shlib_wrap.sh");
my $apps_openssl = bldtop_file("apps", "openssl");
my $server_pem   = srctop_file("test", "certs", "servercert.pem");
my $server_key   = srctop_file("test", "certs", "serverkey.pem");

# Start s_server; accept 2 connections (first connect + one reconnect).
# Use -tls1_2 so the handshake succeeds in builds that disable TLS 1.3 groups.
my @s_server_cmd = ("s_server", "-accept", "0", "-naccept", "2",
                    "-tls1_2", "-cert", $server_pem, "-key", $server_key);
my $s_server_pid = open3(my $s_server_i, my $s_server_o, my $s_server_e = gensym,
                         $shlib_wrap, $apps_openssl, @s_server_cmd);

# Parse server port from ACCEPT line
my $port = "0";
while (<$s_server_o>) {
    chomp;
    if (/^ACCEPT 0\.0\.0\.0:(\d+)/ || /^ACCEPT \[::\]:(\d+)/) {
        $port = $1;
        last;
    }
}
ok($port ne "0", "s_server bound to a port");
# Give server time to be in accept() before client connects (avoids connection refused in CI)
select(undef, undef, undef, 1.0);

# Start s_client with -reconnect so it does one handshake then reconnects.
# Use 127.0.0.1 (IPv4) and -tls1_2 to match server and avoid "no suitable groups" in restricted builds.
my @s_client_cmd = ("s_client", "-connect", "127.0.0.1:$port",
                    "-tls1_2", "-reconnect");
my $s_client_pid = open3(my $s_client_i, my $s_client_o, my $s_client_e = gensym,
                         $shlib_wrap, $apps_openssl, @s_client_cmd);

# Read client stdout until we see "drop connection and then reconnect"
# (so we know the reconnect path was taken), then send Q to quit.
# When stdout is a pipe, C may use full buffering so the message can appear
# only after we send Q and the client flushes on exit; drain after Q too.
my $reconnect_seen = 0;
my $output = '';
my $deadline = time() + 60;
while (time() < $deadline) {
    my $readfds = '';
    vec($readfds, fileno($s_client_o), 1) = 1;
    my $n = select($readfds, undef, undef, 0.25);
    if ($n > 0 && !eof($s_client_o)) {
        my $buf;
        my $read = sysread($s_client_o, $buf, 256);
        if (defined $read && $read > 0) {
            $output .= $buf;
            $reconnect_seen = 1 if $output =~ /drop connection and then reconnect/;
        }
    }
    last if $reconnect_seen;
}
print $s_client_i "Q\n";
# Drain stdout briefly so we see any buffered "drop connection and then reconnect"
my $drain_deadline = time() + 3;
while (time() < $drain_deadline && !eof($s_client_o)) {
    my $readfds = '';
    vec($readfds, fileno($s_client_o), 1) = 1;
    my $n = select($readfds, undef, undef, 0.1);
    if ($n > 0 && !eof($s_client_o)) {
        my $buf;
        my $read = sysread($s_client_o, $buf, 4096);
        last if !defined $read || $read == 0;
        $output .= $buf;
        $reconnect_seen = 1 if $output =~ /drop connection and then reconnect/;
    }
}
close($s_client_i);
waitpid($s_client_pid, 0);

# Drain stderr for diagnostics on failure (child has exited, read until EOF or brief timeout)
my $stderr = '';
my $stderr_deadline = time() + 2;
while (time() < $stderr_deadline) {
    my $readfds = '';
    vec($readfds, fileno($s_client_e), 1) = 1;
    my $n = select($readfds, undef, undef, 0.1);
    last if $n <= 0 && $stderr eq '';
    if ($n > 0) {
        my $buf;
        my $read = sysread($s_client_e, $buf, 4096);
        last if !defined $read || $read == 0;
        $stderr .= $buf;
    }
}
close($s_client_e);

# Clean up server
kill 'HUP', $s_server_pid;
waitpid($s_server_pid, 0);

unless ($reconnect_seen) {
    diag("s_client stdout (expected 'drop connection and then reconnect'):");
    diag($output) if $output ne '';
    diag("s_client stderr:") if $stderr ne '';
    diag($stderr) if $stderr ne '';
}
ok($reconnect_seen, "s_client -reconnect triggered reconnect");
# Exit code 0 when built with LeakSanitizer means no leak was reported
ok(($? >> 8) == 0, "s_client exited successfully (no leak)");
