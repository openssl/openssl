#! /usr/bin/env perl
# Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
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
use Symbol 'gensym';

# servers randomly pick a port, then set this for clients to use
# we also record the pid so we can kill it later if needed
my $s_server_port = 0;
my $s_server_pid = 0;
my $s_client_match = 0;

my $test_name = "test_ech_client_server";
setup($test_name);

plan skip_all => "$test_name requires EC cryptography"
    if disabled("ec") || disabled("ecx");
plan skip_all => "$test_name requires sock enabled"
    if disabled("sock");
plan skip_all => "$test_name requires TLSv1.3 enabled"
    if disabled("tls1_3");
plan skip_all => "$test_name is not available Windows or VMS"
    if $^O =~ /^(VMS|MSWin32|msys)$/;

plan tests => 6;

my $shlib_wrap   = bldtop_file("util", "shlib_wrap.sh");
my $apps_openssl = bldtop_file("apps", "openssl");

my $echconfig_pem         = srctop_file("test", "certs", "ech-eg.pem");
my $badconfig_pem         = srctop_file("test", "certs", "ech-mid.pem");
my $server_pem            = srctop_file("test", "certs", "echserver.pem");
my $server_key            = srctop_file("test", "certs", "echserver.key");
my $root_pem              = srctop_file("test", "certs", "rootcert.pem");

sub start_ech_client_server
{
    my ( $b64ech, $winpattern ) = @_;

    # start an s_server listening on some random port, with ECH enabled
    # and willing to accept one request 

    # openssl s_server -accept 0 -naccept 1
    #                  -key $server_key -cert $server_cert
    #                  -key2 $server_key -cert2 $server_cert
    #                  -ech_key $echconfig_pem
    #                  -servername example.com
    #                  -tls1_3 
    my @s_server_cmd = ("s_server", "-accept", "0", "-naccept", "1",
                        "-cert", $server_pem, "-key", $server_key,
                        "-cert2", $server_pem, "-key2", $server_key,
                        "-ech_key", $echconfig_pem,
                        "-servername", "example.com",
                        "-tls1_3");
    print("@s_server_cmd\n");
    $s_server_pid = open3(my $s_server_i, my $s_server_o,
                             my $s_server_e = gensym,
                             $shlib_wrap, $apps_openssl, @s_server_cmd);
    # we're looking for...
    # ACCEPT 0.0.0.0:45921
    # ACCEPT [::]:45921
    $s_server_port = "0";
    while (<$s_server_o>) {
        print($_);
        chomp;
        if (/^ACCEPT 0.0.0.0:(\d+)/) {
            $s_server_port = $1;
            last;
        } elsif (/^ACCEPT \[::\]:(\d+)/) {
            $s_server_port = $1;
            last;
        } elsif (/^Using default/) {
            ;
        } elsif (/^Added ECH key pair/) {
            ;
        } elsif (/^Loaded/) {
            ;
        } elsif (/^Setting secondary/) {
            ;
        } else {
            last;
        }
    }
    # openssl s_client -connect localhost:NNNNN
    #                  -servername server.example
    #                  -CAfile test/certs/rootcert.pem
    #                  -ech_config_list "ADn+...AA="
    #                  -prexit
    my @s_client_cmd;
    if ($b64ech ne "GREASE" ) {
        @s_client_cmd = ("s_client",
                            "-connect", "localhost:$s_server_port",
                            "-servername", "server.example",
                            "-CAfile", $root_pem,
                            "-ech_config_list", $b64ech,
                            "-prexit");
                        # for loadsa debugging add...
                        # "-debug", "-msg", "-trace", "-tlsextdebug");
    } else {
        @s_client_cmd = ("s_client",
                            "-connect", "localhost:$s_server_port",
                            "-servername", "server.example",
                            "-CAfile", $root_pem,
                            "-ech_grease",
                            "-prexit");
    }
    print("@s_client_cmd\n");
    local (*sc_input);
    my $s_client_pid = open3(*sc_input, my $s_client_o,
                             my $s_client_e = gensym,
                             $shlib_wrap, $apps_openssl, @s_client_cmd);
    print sc_input "Q\n";
    close(sc_input);
    waitpid($s_client_pid, 0);
    # the output from s_client that we want to check is written to its
    # stdout, e.g: "^ECH: success, yay!"
    $s_client_match = 0;
    while (<$s_client_o>) {
        print($_);
        chomp;
        if (/$winpattern/) {
            $s_client_match = 1;
            last;
        }
    }
    my $stillthere = kill 0, $s_server_pid;
    if ($stillthere) {
       print("s_server process ($s_server_pid) is not dead yet.\n");
       kill 'HUP', $s_server_pid;
    }
}

sub basic_test {
    print("\n\nBasic test.\n");
    # extract b64 encoded ECHConfigList from pem file
    my $b64 = "";
    my $inwanted = 0;
    open( my $fh, '<', $echconfig_pem ) or die "Can't open $echconfig_pem $!";
    while( my $line = <$fh>) {
        chomp $line;
        if ( $line =~ /^-----BEGIN ECHCONFIG/) {
            $inwanted = 1;
        } elsif ( $line =~ /^-----END ECHCONFIG/) {
            $inwanted = 0;
        } elsif ($inwanted == 1) {
            $b64 .= $line;
        }
    }
    print("base64 ECHConfigList: $b64\n");
    my $win = "^ECH: success";
    start_ech_client_server($b64, $win);
    ok($s_server_port ne "0", "s_server port check");
    print("s_server ready, on port $s_server_port pid: $s_server_pid\n");
    ok($s_client_match == 1, "s_client using with ECH");
}

sub wrong_test {
    print("\n\nWrong ECHConfig test.\n");
    # hardcoded 'cause we want a fail
    my $b64="AEH+DQA91wAgACCBdNrnZxqNrUXSyimqqnfmNG4lHtVsbmaaIeRoUoFWFQAEAAEAAQAOc2VydmVyLmV4YW1wbGUAAA==";
    my $win="^ECH: failed.retry-configs: -105";
    start_ech_client_server($b64, $win);
    ok($s_server_port ne "0", "s_server port check");
    print("s_server ready, on port $s_server_port pid: $s_server_pid\n");
    ok($s_client_match == 1, "s_client using with ECH");
}

sub grease_test {
    print("\n\nWrong ECHConfig test.\n");
    # hardcoded 'cause we want a fail
    my $b64="GREASE";
    my $win="^ECH: GREASE";
    start_ech_client_server($b64, $win);
    ok($s_server_port ne "0", "s_server port check");
    print("s_server ready, on port $s_server_port pid: $s_server_pid\n");
    ok($s_client_match == 1, "s_client using with ECH");
}

basic_test();
wrong_test();
grease_test();
