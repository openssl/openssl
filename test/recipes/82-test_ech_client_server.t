#! /usr/bin/env perl
# Copyright 2023-2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use IPC::Open3;
use OpenSSL::Test qw/:DEFAULT srctop_file srctop_dir bldtop_file/;
use OpenSSL::Test::Utils;
use Symbol 'gensym';

# servers randomly pick a port, then set this for clients to use
# we also record the pid so we can kill it later if needed
my $s_server_port = 0;
my $s_server_pid = 0;
my $s_client_match = 0;

my $test_name = "test_ech_client_server";
setup($test_name);

plan skip_all => "$test_name requires ECH"
    if disabled("ech");
plan skip_all => "$test_name requires EC cryptography"
    if disabled("ec") || disabled("ecx");
plan skip_all => "$test_name requires sock enabled"
    if disabled("sock");
plan skip_all => "$test_name requires TLSv1.3 enabled"
    if disabled("tls1_3");
plan skip_all => "$test_name is not available Windows or VMS"
    if $^O =~ /^(VMS|MSWin32|msys)$/;

plan tests => 22;

my $shlib_wrap   = bldtop_file("util", "shlib_wrap.sh");
my $apps_openssl = bldtop_file("apps", "openssl");

my $echconfig_pem         = srctop_file("test", "certs", "echdir", "ech-eg.pem");
my $badconfig_pem         = srctop_file("test", "certs", "echdir", "ech-mid.pem");
my $server_pem            = srctop_file("test", "certs", "echserver.pem");
my $server_key            = srctop_file("test", "certs", "echserver.key");
my $root_pem              = srctop_file("test", "certs", "rootcert.pem");
my $ech_dir               = srctop_dir("test", "certs", "echdir" );

sub extract_ecl()
{
    # extract b64 encoded ECHConfigList from pem file
    my $lb64 = "";
    my $inwanted = 0;
    open( my $fh, '<', $echconfig_pem ) or die "Can't open $echconfig_pem $!";
    while( my $line = <$fh>) {
        chomp $line;
        if ( $line =~ /^-----BEGIN ECHCONFIG/) {
            $inwanted = 1;
        } elsif ( $line =~ /^-----END ECHCONFIG/) {
            $inwanted = 0;
        } elsif ($inwanted == 1) {
            $lb64 .= $line;
        }
    }
    print("base64 ECHConfigList: $lb64\n");
    return($lb64);
}

my $good_b64 = extract_ecl();

sub start_ech_client_server
{
    my ( $test_type, $winpattern ) = @_;

    # start an s_server listening on some random port, with ECH enabled
    # and willing to accept one request

    # openssl s_server -accept 0 -naccept 1
    #                  -key $server_key -cert $server_cert
    #                  -key2 $server_key -cert2 $server_cert
    #                  -ech_key $echconfig_pem
    #                  -servername example.com
    #                  -tls1_3
    my @s_server_cmd;
    if ($test_type eq "cid-free" ) {
        # turn on trial-decrypt, so client can use random CID
        @s_server_cmd = ("s_server", "-accept", "0", "-naccept", "1",
                         "-cert", $server_pem, "-key", $server_key,
                         "-cert2", $server_pem, "-key2", $server_key,
                         "-ech_key", $echconfig_pem,
                         "-servername", "example.com",
                         "-ech_trialdecrypt",
                         "-tls1_3");
     } elsif ($test_type eq "keydir" ) {
        # load keys from key dir (some will fail)
        @s_server_cmd = ("s_server", "-accept", "0", "-naccept", "1",
                         "-cert", $server_pem, "-key", $server_key,
                         "-cert2", $server_pem, "-key2", $server_key,
                         "-ech_dir", $ech_dir,
                         "-ech_noretry_dir", $ech_dir,
                         "-servername", "example.com",
                         "-tls1_3");
    } else {
        # default for all other tests (for now)
        @s_server_cmd = ("s_server", "-accept", "0", "-naccept", "1",
                         "-cert", $server_pem, "-key", $server_key,
                         "-cert2", $server_pem, "-key2", $server_key,
                         "-ech_key", $echconfig_pem,
                         "-servername", "example.com",
                         "-ech_greaseretries",
                         "-tls1_3");
    }
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
        } elsif (/^Added (\d+) ECH/) {
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
    if ($test_type eq "GREASE-suite" ) {
        # GREASE with suite
        @s_client_cmd = ("s_client",
                         "-connect", "localhost:$s_server_port",
                         "-servername", "server.example",
                         "-CAfile", $root_pem,
                         "-ech_grease_suite", "0x21,2,3",
                         "-prexit");
     } elsif ($test_type eq "bad-GREASE-suite" ) {
        # bad GREASE suite
        @s_client_cmd = ("s_client",
                         "-connect", "localhost:$s_server_port",
                         "-servername", "server.example",
                         "-CAfile", $root_pem,
                         "-ech_grease_suite", "thisisnotagoodone",
                         "-prexit");
    } elsif ($test_type eq "lots-of-options" ) {
        # real ECH with lots of options
        @s_client_cmd = ("s_client",
                         "-connect", "localhost:$s_server_port",
                         "-servername", "server.example",
                         "-CAfile", $root_pem,
                         "-ech_config_list", $good_b64,
                         "-ech_outer_sni", "foodle.doodle",
                         "-ech_select", "0",
                         "-alpn", "http/1.1",
                         "-ech_outer_alpn", "http451",
                         "-prexit");
    } elsif ($test_type eq "GREASE-type" ) {
        # GREASE with type
        @s_client_cmd = ("s_client",
                         "-connect", "localhost:$s_server_port",
                         "-servername", "server.example",
                         "-CAfile", $root_pem,
                         "-ech_grease_type", "12345",
                         "-prexit");
    } elsif ($test_type eq "GREASE" ) {
        # GREASE with suite
        @s_client_cmd = ("s_client",
                         "-connect", "localhost:$s_server_port",
                         "-servername", "server.example",
                         "-CAfile", $root_pem,
                         "-ech_grease",
                         "-prexit");
    } elsif ($test_type eq "no-outer" ) {
        # Real ECH, no outer SNI
        @s_client_cmd = ("s_client",
                         "-connect", "localhost:$s_server_port",
                         "-servername", "server.example",
                         "-CAfile", $root_pem,
                         "-ech_config_list", $good_b64,
                         "-ech_no_outer_sni",
                         "-prexit");
    } elsif ($test_type eq "bad-ech" ) {
        # bad ECH
        @s_client_cmd = ("s_client",
                         "-connect", "localhost:$s_server_port",
                         "-servername", "server.example",
                         "-CAfile", $root_pem,
                         "-ech_config_list", "AEH+DQA91wAgACCBdNrnZxqNrUXSyimqqnfmNG4lHtVsbmaaIeRoUoFWFQAEAAEAAQAOc2VydmVyLmV4YW1wbGUAAA==",
                         "-prexit");
    } elsif ($test_type eq "cid-free" ) {
        # Real ECH, ignore CID
        @s_client_cmd = ("s_client",
                         "-connect", "localhost:$s_server_port",
                         "-servername", "server.example",
                         "-CAfile", $root_pem,
                         "-ech_config_list", $good_b64,
                         "-ech_ignore_cid",
                         "-prexit");
    } elsif ($test_type eq "cid-wrong" ) {
        # Real ECH, ignore CID, no trial decrypt
        @s_client_cmd = ("s_client",
                         "-connect", "localhost:$s_server_port",
                         "-servername", "server.example",
                         "-CAfile", $root_pem,
                         "-ech_config_list", $good_b64,
                         "-ech_ignore_cid",
                         "-prexit");
    } else {
        # Real ECH, and default
        @s_client_cmd = ("s_client",
                         "-connect", "localhost:$s_server_port",
                         "-servername", "server.example",
                         "-CAfile", $root_pem,
                         "-ech_config_list", $good_b64,
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
    my $tt = "basic";
    my $win = "^ECH: success";
    start_ech_client_server($tt, $win);
    ok($s_server_port ne "0", "s_server port check");
    print("s_server ready, on port $s_server_port pid: $s_server_pid\n");
    ok($s_client_match == 1, "s_client with ECH on command line");
}

sub wrong_test {
    print("\n\nWrong ECHConfig test.\n");
    # hardcoded 'cause we want a fail
    my $tt="bad-ech",
    my $win="^ECH: failed.retry-configs: -105";
    start_ech_client_server($tt, $win);
    ok($s_server_port ne "0", "s_server port check");
    print("s_server ready, on port $s_server_port pid: $s_server_pid\n");
    ok($s_client_match == 1, "s_client with bad ECH");
}

sub grease_test {
    print("\n\nGREASE ECHConfig test.\n");
    my $tt="GREASE";
    my $win="^ECH: GREASE";
    start_ech_client_server($tt, $win);
    ok($s_server_port ne "0", "s_server port check");
    print("s_server ready, on port $s_server_port pid: $s_server_pid\n");
    ok($s_client_match == 1, "s_client with GREASE ECH");
}

sub grease_suite_test {
    print("\n\nGREASE suite ECHConfig test.\n");
    my $tt="GREASE-suite";
    my $win="^ECH: GREASE";
    start_ech_client_server($tt, $win);
    ok($s_server_port ne "0", "s_server port check");
    print("s_server ready, on port $s_server_port pid: $s_server_pid\n");
    ok($s_client_match == 1, "s_client with GREASE-suite ECH");
}

sub bad_grease_suite_test {
    print("\n\nGREASE suite ECHConfig test.\n");
    my $tt="bad-GREASE-suite";
    my $win="^ECH: NOT CONFIGURED";
    start_ech_client_server($tt, $win);
    ok($s_server_port ne "0", "s_server port check");
    print("s_server ready, on port $s_server_port pid: $s_server_pid\n");
    ok($s_client_match == 1, "s_client with bad GREASE-suite ECH");
}

sub grease_type_test {
    print("\n\nGREASE type ECH test.\n");
    my $tt="GREASE-type";
    my $win="^ECH: GREASE";
    start_ech_client_server($tt, $win);
    ok($s_server_port ne "0", "s_server port check");
    print("s_server ready, on port $s_server_port pid: $s_server_pid\n");
    ok($s_client_match == 1, "s_client with GREASE-type ECH");
}

sub lots_of_options_test {
    print("\n\nLots of options ECH test.\n");
    my $tt="lots-of-options";
    my $win="^ECH: success";
    start_ech_client_server($tt, $win);
    ok($s_server_port ne "0", "s_server port check");
    print("s_server ready, on port $s_server_port pid: $s_server_pid\n");
    ok($s_client_match == 1, "s_client with lots of ECH options");
}

sub no_outer_test {
    print("\n\nNo outer SNI test.\n");
    my $tt = "no-outer";
    my $win = "^ECH: success";
    start_ech_client_server($tt, $win);
    ok($s_server_port ne "0", "s_server port check");
    print("s_server ready, on port $s_server_port pid: $s_server_pid\n");
    ok($s_client_match == 1, "s_client with no outer SNI ECH");
}

sub cid_free_test {
    print("\n\nIgnore CIDs test.\n");
    my $tt = "cid-free";
    my $win = "^ECH: success";
    start_ech_client_server($tt, $win);
    ok($s_server_port ne "0", "s_server port check");
    print("s_server ready, on port $s_server_port pid: $s_server_pid\n");
    ok($s_client_match == 1, "s_client/s_server with no CID/trial decrypt");
}

sub cid_wrong_test {
    print("\n\nIgnore CIDs test.\n");
    my $tt = "cid-wrong";
    my $win = "^ECH: failed";
    start_ech_client_server($tt, $win);
    ok($s_server_port ne "0", "s_server port check");
    print("s_server ready, on port $s_server_port pid: $s_server_pid\n");
    ok($s_client_match == 1, "s_client/s_server with no CID/no trial decrypt");
}

sub keydir_test {
    print("\n\nServer using key dir test.\n");
    my $tt = "keydir";
    my $win = "^ECH: success";
    start_ech_client_server($tt, $win);
    ok($s_server_port ne "0", "s_server port check");
    print("s_server ready, on port $s_server_port pid: $s_server_pid\n");
    ok($s_client_match == 1, "s_server using ech keydir on command line");
}

basic_test();
wrong_test();
grease_test();
grease_suite_test();
bad_grease_suite_test();
grease_type_test();
lots_of_options_test();
no_outer_test();
cid_free_test();
cid_wrong_test();
keydir_test();

