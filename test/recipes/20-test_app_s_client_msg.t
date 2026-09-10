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
use OpenSSL::Test qw/:DEFAULT result_dir srctop_file bldtop_file/;
use OpenSSL::Test::Utils;

my $test_name = "test_app_s_client_msg";
setup($test_name);

plan skip_all => "$test_name needs sock enabled"
    if disabled("sock");
plan skip_all => "$test_name is not available on Windows or VMS"
    if $^O =~ /^(VMS|MSWin32|msys)$/;

my $shlib_wrap   = bldtop_file("util", "wrap.pl");
my $apps_openssl = bldtop_file("apps", "openssl");
my $server_pem   = srctop_file("test", "certs", "servercert.pem");
my $server_key   = srctop_file("test", "certs", "serverkey.pem");
my $resultdir    = result_dir();

# Each case exercises the s_client message callback (-msg) over a different
# protocol version. Every record must be decoded; before the DTLSv1.2 fix such
# records were logged as "Not TLS data or unknown version".
my @cases = (
    { name => "TLSv1.2",  flag => "-tls1_2",  disabled => "tls1_2" },
    { name => "TLSv1.3",  flag => "-tls1_3",  disabled => "tls1_3" },
    { name => "DTLSv1.2", flag => "-dtls1_2", disabled => "dtls1_2" },
);
@cases = grep { !disabled($_->{disabled}) } @cases;

plan tests => scalar @cases;

# Run one s_server/s_client handshake logging protocol messages via -msgfile.
# Returns the number of decoded and undecoded records seen in the log.
sub run_case
{
    my $case = shift;
    my $msgfile = "$resultdir/s_client-msg-$case->{disabled}.txt";
    my ($records, $unknown) = (0, 0);

    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm 60;

        # Start a server speaking just this protocol version
        my @s_server_cmd = ("s_server", $case->{flag}, "-accept", "0",
                            "-naccept", "1", "-cert", $server_pem,
                            "-key", $server_key);
        my $s_server_pid = open3(my $s_server_i, my $s_server_o, my $s_server_e,
                                 $shlib_wrap, $apps_openssl, @s_server_cmd);

        # Figure out what port it is listening on
        my $server_port = "0";
        while (<$s_server_o>) {
            print($_);
            chomp;
            if (/^ACCEPT \S+?:(\d+)/) {
                $server_port = $1;
                last;
            } elsif (/^Using default/) {
                ;
            } else {
                last;
            }
        }

        # Connect a client that logs the protocol messages to a file. -msgfile
        # sets the log destination but selects SSL_trace; the trailing -msg
        # switches the callback back to msg_cb (the code under test) while
        # keeping the file destination.
        my @s_client_cmd = ("s_client", $case->{flag}, "-msgfile", $msgfile,
                            "-msg", "-connect", "localhost:$server_port");
        my $s_client_pid = open3(my $s_client_i, my $s_client_o, my $s_client_e,
                                 $shlib_wrap, $apps_openssl, @s_client_cmd);

        # Quit the client once connected, then reap both processes
        print $s_client_i "Q\n";
        waitpid($s_client_pid, 0);
        kill 'HUP', $s_server_pid if kill 0, $s_server_pid;
        waitpid($s_server_pid, 0);

        alarm 0;
    };
    die $@ if $@ && $@ ne "timeout\n";
    print("TIMEOUT: $case->{name} timed out\n") if $@;

    if (open(my $fh, '<', $msgfile)) {
        while (<$fh>) {
            $records++ if /^(?:>>>|<<<)/;
            $unknown++ if /Not TLS data or unknown version/;
        }
        close($fh);
    }
    return ($records, $unknown);
}

foreach my $case (@cases) {
    my ($records, $unknown) = run_case($case);
    ok($records > 0 && $unknown == 0,
       "s_client -msg decodes all $case->{name} records");
}
