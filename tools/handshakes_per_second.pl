#! /usr/bin/env perl
# Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;
use Getopt::Std;

#our $opt_n = 0;
#getopts('n') or die "Invalid option: $!\n";

sub do_fork {
    my @args = @_;

    my $pid = fork();
    if (!defined($pid)) {
        die "Error: Cannot fork: $!";
    } elsif ($pid == 0) {
        exec {$args[0]} @args;
        die "Error: Cannot exec $_[0]: $!";
    } else {
        return $pid;
    }
}

sub do_wait {
    my $pid = shift;
    my $name = shift;

    my $ret = waitpid($pid, 0);
    die("Cannot wait for process '$name'") if $pid == -1;
    return $?;
}

# Daniel: How to call agains actual library?
my $server_pid = do_fork('tools/handshakes_per_second_helper', 'server', '127.0.0.1', 1024, 'localhost', 'key.pem', 'cert.pem', 2048);
my $client_pid = do_fork('tools/handshakes_per_second_helper', 'client', '127.0.0.1', 1024, 'localhost', 'key.pem', 'cert.pem', 2048);


if (my $ret = do_wait($server_pid, "server")) {
    warn("Server process failed: $ret");
}
if (my $ret = do_wait($client_pid, "client")) {
    warn("Client process failed: $ret");
}