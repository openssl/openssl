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
use OpenSSL::Test qw/:DEFAULT result_file srctop_file bldtop_file/;
use OpenSSL::Test::Utils;
use Symbol 'gensym';

my $test_name = "test_app_s_client_no_interactive";
setup($test_name);

plan skip_all => "$test_name needs sock enabled"
    if disabled("sock");
plan skip_all => "$test_name needs some TLS protocols to be enabled"
    if alldisabled(available_protocols("tls"));
plan skip_all => "$test_name needs ec, ecx or dh for TLS key exchange"
    if disabled("ec") && disabled("ecx") && disabled("dh");
plan skip_all => "$test_name is not available on Windows or VMS"
    if $^O =~ /^(VMS|MSWin32|msys)$/;

plan tests => 3;

my $shlib_wrap   = bldtop_file("util", "wrap.pl");
my $apps_openssl = bldtop_file("apps", "openssl");
my $server_pem   = srctop_file("test", "certs", "servercert.pem");
my $server_key   = srctop_file("test", "certs", "serverkey.pem");

my @s_server_cmd = ("s_server", "-accept", "0", "-naccept", "1",
                    "-cert", $server_pem, "-key", $server_key);
my $s_server_pid = open3(my $s_server_i, my $s_server_o,
                         my $s_server_e = gensym,
                         $shlib_wrap, $apps_openssl, @s_server_cmd);

my $port = "0";
while (<$s_server_o>) {
    chomp;
    if    (/^ACCEPT \S*?:(\d+)/) { $port = $1; last; }
    elsif (/^Using default/)     { ; }
    else                         { last; }
}
ok($port ne "0", "s_server port check");

SKIP: {
    skip "could not start s_server", 2 if $port eq "0";

    # s_client -no-interactive has to finish on its own once the peer is
    # done with it, whatever stdin is doing.  Here stdin is a pipe whose
    # writer stays open and never sends anything, which is what a test
    # harness or a script that pipes into s_client looks like.  Such a pipe
    # never becomes readable, and on Windows the loop used to poll it once a
    # second instead of taking the -no-interactive exit.  The writer
    # ($s_client_i) must stay open for the whole run: closing it would make
    # the pipe readable at EOF and hide the problem.
    my $stdout_file = result_file("s_client-no-interactive-stdout.txt");
    my $stderr_file = result_file("s_client-no-interactive-stderr.txt");
    open my $stdout, ">", $stdout_file
        or BAIL_OUT("failed to open $stdout_file: $!");
    open my $stderr, ">", $stderr_file
        or BAIL_OUT("failed to open $stderr_file: $!");

    my @s_client_cmd = ("s_client", "-no-interactive",
                        "-connect", "localhost:$port");
    my $s_client_pid = open3(my $s_client_i,
                             ">&" . fileno($stdout), ">&" . fileno($stderr),
                             $shlib_wrap, $apps_openssl, @s_client_cmd);

    my $exited = 0;
    my $status = -1;
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm 60;
        waitpid($s_client_pid, 0);
        alarm 0;
        $exited = 1;
        $status = $?;
    };
    alarm 0;

    if (!$exited) {
        kill 'KILL', $s_client_pid;
        waitpid($s_client_pid, 0);
    }
    close $s_client_i;
    close $stdout;
    close $stderr;

    ok($exited, "s_client -no-interactive exits with an idle stdin pipe");
    is($status, 0, "s_client -no-interactive exit status");
}

kill 'HUP', $s_server_pid;
waitpid($s_server_pid, 0);
