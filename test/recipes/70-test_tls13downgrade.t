#! /usr/bin/env perl
# Copyright 2017-2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;
use Cwd qw(abs_path);

my $test_name = "test_tls13downgrade";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the module feature enabled"
    if disabled("module");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs EC or DH enabled"
    if disabled("ec") && disabled("dh");

$ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("test"));

use constant {
    DOWNGRADE_TO_TLS_1_2 => 0,
    DOWNGRADE_TO_TLS_1_1 => 1,
    FALLBACK_FROM_TLS_1_3 => 2,
    DOWNGRADE_TO_TLS_1_2_WITH_TLS_1_1_SIGNAL => 3,
    DOWNGRADE_TO_TLS_1_1_WITH_TLS_1_2_SIGNAL => 4,
};

my $testcount = 8;
plan tests => 2 * $testcount;

my $testtype;

SKIP: {
    skip "TLS 1.2 or 1.3 is disabled", $testcount if disabled("tls1_3")
                                                     || disabled("tls1_2");
    # Run tests with TLS
    run_tests(0);
}

SKIP: {
    # TODO(DTLSv1.3): This test currently does not work for DTLS. It gets stuck
    # in the first test case.
    skip "Test does not work correctly currently", $testcount;

    skip "DTLS 1.2 or 1.3 is disabled", $testcount if disabled("dtls1_3")
                                                      || disabled("dtls1_2");
    skip "DTLSProxy does not work on Windows", $testcount if $^O =~ /^(MSWin32)$/;
    run_tests(1);
}

sub run_tests
{
    my $run_test_as_dtls = shift;
    my $proto1_1 = $run_test_as_dtls == 1 ? "DTLSv1" : "TLSv1.1";
    my $proto1_2 = $run_test_as_dtls == 1 ? "DTLSv1.2" : "TLSv1.2";
    my $proto1_3 = $run_test_as_dtls == 1 ? "DTLSv1.3" : "TLSv1.3";

    my $proxy;
    if ($run_test_as_dtls == 1) {
        $proxy = TLSProxy::Proxy->new_dtls(
            undef,
            cmdstr(app([ "openssl" ]), display => 1),
            srctop_file("apps", "server.pem"),
            (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
        );
    } else {
        $proxy = TLSProxy::Proxy->new(
            undef,
            cmdstr(app([ "openssl" ]), display => 1),
            srctop_file("apps", "server.pem"),
            (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
        );
    }

    my $client_flags = "";

    if ($run_test_as_dtls == 1) {
        # TLSProxy does not handle partial messages for DTLS.
        $client_flags = $client_flags." -groups DEFAULT:-?X25519MLKEM768";
    }

    #Test 1: Downgrade from (D)TLSv1.3 to (D)TLSv1.2
    $proxy->clear();
    $proxy->filter(\&downgrade_filter);
    $proxy->clientflags($client_flags);
    $testtype = DOWNGRADE_TO_TLS_1_2;
    skip "Unable to start up Proxy for tests", $testcount if !$proxy->start() && !$run_test_as_dtls;
    ok(is_illegal_parameter_client_alert(), "Downgrade ".$proto1_3." to ".$proto1_2);

    #Test 2: Downgrade from (D)TLSv1.3 to (D)TLSv1.2 (server sends (D)TLSv1.1 signal)
    $proxy->clear();
    $testtype = DOWNGRADE_TO_TLS_1_2_WITH_TLS_1_1_SIGNAL;
    $proxy->clientflags($client_flags);
    $proxy->start();
    ok(is_illegal_parameter_client_alert(),
        "Downgrade from ".$proto1_3." to ".$proto1_2." (server sends ".$proto1_1." signal)");

    #Test 3: Client falls back from (D)TLSv1.3 (server does not support the
    #        fallback SCSV)
    $proxy->clear();
    $proxy->filter(\&downgrade_filter);
    $testtype = FALLBACK_FROM_TLS_1_3;
    $proxy->clientflags("-fallback_scsv -max_protocol ".$proto1_2);
    $proxy->start();
    ok(is_illegal_parameter_client_alert(), "Fallback from ".$proto1_3);

    $client_flags = "-min_protocol ".$proto1_1." -cipher DEFAULT:\@SECLEVEL=0";
    if ($run_test_as_dtls == 1) {
        # TLSProxy does not handle partial messages for DTLS.
        $client_flags = $client_flags." -groups DEFAULT:-?X25519MLKEM768";
    }
    my $server_flags = "-min_protocol ".$proto1_1;
    my $ciphers = "AES128-SHA:\@SECLEVEL=0";

    SKIP: {
        skip "TLSv1.1 disabled", 3
            if !$run_test_as_dtls && disabled("tls1_1");
        skip "DTLSv1 disabled", 3
            if $run_test_as_dtls == 1 && disabled("dtls1");

        #Test 4: Downgrade from (D)TLSv1.3 to TLSv1.1/DTLSv1
        $proxy->clear();
        $testtype = DOWNGRADE_TO_TLS_1_1;
        $proxy->clientflags($client_flags);
        $proxy->serverflags($server_flags);
        $proxy->ciphers($ciphers);
        $proxy->start();
        ok(is_illegal_parameter_client_alert(), "Downgrade ".$proto1_3." to ".$proto1_1);

        #Test 5: Downgrade from (D)TLSv1.3 to TLSv1.1/DTLSv1 (server sends (D)TLSv1.2 signal)
        $proxy->clear();
        $testtype = DOWNGRADE_TO_TLS_1_1_WITH_TLS_1_2_SIGNAL;
        $proxy->clientflags($client_flags);
        $proxy->serverflags($server_flags);
        $proxy->ciphers($ciphers);
        $proxy->start();
        ok(is_illegal_parameter_client_alert(),
           "Downgrade ".$proto1_3." to ".$proto1_1." (server sends ".$proto1_2." signal)");

        #Test 6: Downgrade from (D)TLSv1.2 to TLSv1.1/DTLSv1
        $proxy->clear();
        $testtype = DOWNGRADE_TO_TLS_1_1;
        $proxy->clientflags($client_flags." -max_protocol ".$proto1_2);
        $proxy->serverflags($server_flags." -max_protocol ".$proto1_2);
        $proxy->ciphers($ciphers);
        $proxy->start();
        ok(is_illegal_parameter_client_alert(), "Downgrade ".$proto1_2." to ".$proto1_1);
    }

    SKIP: {
        skip "TLSv1.1 disabled", 2
            if !$run_test_as_dtls && disabled("tls1_1");
        skip "Missing support for no_dtls1_2", 2 if $run_test_as_dtls == 1;
        #Test 7: A client side protocol "hole" should not be detected as a downgrade
        $proxy->clear();
        $proxy->filter(undef);
        $proxy->clientflags($client_flags." -no_tls1_2");
        $proxy->serverflags($server_flags);
        $proxy->ciphers($ciphers);
        $proxy->start();
        ok(TLSProxy::Message->success(), $proto1_2." client-side protocol hole");

        #Test 8: A server side protocol "hole" should not be detected as a downgrade
        $proxy->clear();
        $proxy->filter(undef);
        $proxy->clientflags($client_flags);
        $proxy->serverflags($server_flags." -no_tls1_2");
        $proxy->ciphers($ciphers);
        $proxy->start();
        ok(TLSProxy::Message->success(), $proto1_2." server-side protocol hole");
    }
}

# Validate that the exchange fails with an illegal parameter alert from
#  the client
sub is_illegal_parameter_client_alert
{
    return 0 unless TLSProxy::Message->fail();
    my $alert = TLSProxy::Message->alert();
    return 1 if !$alert->server()
                && $alert->description()
                   == TLSProxy::Message::AL_DESC_ILLEGAL_PARAMETER;
    return 0;
}

sub downgrade_filter
{
    my $proxy = shift;

    # We're only interested in the initial ClientHello except if we are expecting
    # DTLS1.2 handshake in which case the client will send a second ClientHello
    my $dtls12hs = $proxy->isdtls && ($testtype == FALLBACK_FROM_TLS_1_3
                                      || $testtype == DOWNGRADE_TO_TLS_1_2_WITH_TLS_1_1_SIGNAL
                                      || $testtype == DOWNGRADE_TO_TLS_1_1_WITH_TLS_1_2_SIGNAL);
    my $client_hello = $proxy->flight == 0 || ($dtls12hs && $proxy->flight == 2);
    my $server_hello = ($dtls12hs && $proxy->flight == 3)
                        || (!$dtls12hs && $proxy->flight == 1);

    if (!$server_hello && !$client_hello) {
        return;
    }

    my $message = ${$proxy->message_list}[$proxy->flight];

    if ($server_hello == 1 && defined($message)) {
        # Update the last byte of the downgrade signal
        if ($testtype == DOWNGRADE_TO_TLS_1_2_WITH_TLS_1_1_SIGNAL) {
            $message->random(substr($message->random, 0, 31) . "\0");
            $message->repack();
        } elsif ($testtype == DOWNGRADE_TO_TLS_1_1_WITH_TLS_1_2_SIGNAL) {
            $message->random(substr($message->random, 0, 31) . "\1");
            $message->repack();
        }

        return;
    }

    # ClientHello
    if ($client_hello == 1) {
        if ($testtype == FALLBACK_FROM_TLS_1_3) {
            #The default ciphersuite we use for TLSv1.2 without any SCSV
            my @ciphersuites = (TLSProxy::Message::CIPHER_RSA_WITH_AES_128_CBC_SHA);
            $message->ciphersuite_len(2 * scalar @ciphersuites);
            $message->ciphersuites(\@ciphersuites);
        } else {
            my $ext;
            my $version12hi = $proxy->isdtls == 1 ? 0xFE : 0x03;
            my $version12lo = $proxy->isdtls == 1 ? 0xFD : 0x03;
            my $version11hi = $proxy->isdtls == 1 ? 0xFE : 0x03;
            my $version11lo = $proxy->isdtls == 1 ? 0xFF : 0x02;

            if ($testtype == DOWNGRADE_TO_TLS_1_2
                || $testtype == DOWNGRADE_TO_TLS_1_2_WITH_TLS_1_1_SIGNAL) {
                $ext = pack "C3",
                    0x02, # Length
                    $version12hi, $version12lo;
            } else {
                $ext = pack "C3",
                    0x02, # Length
                    $version11hi, $version11lo;
            }

            $message->set_extension(TLSProxy::Message::EXT_SUPPORTED_VERSIONS,
                                    $ext);
        }

        $message->repack();
    }
}

