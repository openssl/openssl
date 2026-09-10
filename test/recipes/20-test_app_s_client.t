#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use IO::Socket::INET;
use OpenSSL::Test qw/:DEFAULT result_file with/;
use OpenSSL::Test::Utils;

setup("test_app_s_client");

plan skip_all => "test_app_s_client needs sock enabled"
    if disabled("sock");
plan skip_all => "test_app_s_client needs IPv4"
    unless have_IPv4();
plan skip_all => "test_app_s_client needs fork"
    if $^O =~ /^(VMS|MSWin32|msys)$/;

plan tests => 5;

my $timeout = 30;
local $SIG{ALRM} = sub { BAIL_OUT("s_client Sieve STARTTLS test timed out") };
alarm($timeout);

my $listener = IO::Socket::INET->new(
    LocalAddr => "127.0.0.1",
    LocalPort => 0,
    Listen => 1,
    Proto => "tcp",
    ReuseAddr => 1,
) or BAIL_OUT("failed to create local Sieve listener: $!");

my $port = $listener->sockport();
my $command_file = result_file("sieve-starttls-command.txt");
my $stdout_file = result_file("s_client-stdout.txt");
my $stderr_file = result_file("s_client-stderr.txt");
my $server_pid = fork();

BAIL_OUT("failed to fork Sieve listener: $!") unless defined $server_pid;

if ($server_pid == 0) {
    eval {
        local $SIG{ALRM} = sub { die "Sieve listener timed out\n" };
        alarm($timeout);

        my $server = $listener->accept()
            or die "failed to accept s_client connection: $!";

        $server->autoflush(1);
        print $server "\"STARTTLS\"\r\nOK\r\n";

        my $command = <$server>;
        open my $fh, ">", $command_file
            or die "failed to open command capture file: $!";
        print $fh $command if defined $command;
        close $fh;

        # This stub only needs to drive s_client through the plaintext
        # Sieve STARTTLS response parser.  After sending an exact two-byte
        # lowercase OK response, it closes instead of performing TLS.  The
        # resulting handshake failure is expected, but sanitizer failures
        # before that are not.
        print $server "ok";
        close $server;
        alarm(0);
    };
    warn $@ if $@;
    exit($@ ? 1 : 0);
}

close $listener;

with({ exit_checker => sub { return shift() < 128; } },
     sub {
         ok(run(app(["openssl", "s_client", "-brief", "-starttls", "sieve",
                     "-connect", "127.0.0.1:$port"],
                    stdin => undef, stdout => $stdout_file,
                    stderr => $stderr_file)),
            "s_client exits without signal");
     });

waitpid($server_pid, 0);
is($?, 0, "Sieve listener completed");

my $command = "";
if (open my $fh, "<", $command_file) {
    local $/;
    $command = <$fh>;
    close $fh;
}
is($command, "STARTTLS\r\n", "s_client sends Sieve STARTTLS command");

my $stderr = "";
if (open my $fh, "<", $stderr_file) {
    local $/;
    $stderr = <$fh>;
    close $fh;
}
unlike($stderr, qr/STARTTLS not supported/,
       "s_client accepts case-insensitive two-byte OK response");
unlike($stderr, qr/AddressSanitizer/,
       "s_client does not trigger AddressSanitizer");

alarm(0);
