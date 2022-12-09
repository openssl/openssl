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

my $server_pid = do_fork('tools/handshakes_per_second', 'server', '127.0.0.1', 1024, 2048);
my $client_pid = do_fork('tools/handshakes_per_second', 'client', '127.0.0.1', 1024, 2048);


waitpid($server_pid, 0);
waitpid($client_pid, 0);