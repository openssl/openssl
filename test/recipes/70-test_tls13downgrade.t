#! /usr/bin/env perl
# Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;

my $test_name = "test_tls13downgrade";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the dynamic engine feature enabled"
    if disabled("engine") || disabled("dynamic-engine");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs EC or DH enabled"
    if disabled("ec") && disabled("dh");

use constant {
    DOWNGRADE_TO_TLS_1_2 => 0,
    DOWNGRADE_TO_TLS_1_1 => 1,
    FALLBACK_FROM_TLS_1_3 => 2,
};

my $testcount = 6;
plan tests => 2 * $testcount;

my $testtype;

SKIP: {
    skip "TLS 1.2 or 1.3 is disabled", $testcount if disabled("tls1_3")
                                                     || disabled("tls1_2");
    # Run tests with TLS
    run_tests(0);
}

SKIP: {
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

    #Test 1: Downgrade from (D)TLSv1.3 to (D)TLSv1.2
    $proxy->clear();
    $proxy->filter(\&downgrade_filter);
    $testtype = DOWNGRADE_TO_TLS_1_2;
    skip "Unable to start up Proxy for tests", $testcount if !$proxy->start() &&
                                                             !TLSProxy::Message->fail();
    ok(TLSProxy::Message->fail(), "Downgrade ".$proto1_3." to ".$proto1_2);

    #Test 2: Downgrade from (D)TLSv1.3 to TLSv1.1/DTLSv1
    $proxy->clear();
    $testtype = DOWNGRADE_TO_TLS_1_1;
    $proxy->start();
    ok(TLSProxy::Message->fail(), "Downgrade ".$proto1_3." to ".$proto1_1);

    #Test 3: Downgrade from (D)TLSv1.2 to TLSv1.1/DTLSv1
    $proxy->clear();
    $proxy->clientflags("-max_protocol ".$proto1_2);
    $proxy->serverflags("-max_protocol ".$proto1_2);
    $proxy->start();
    ok(TLSProxy::Message->fail(), "Downgrade ".$proto1_2." to ".$proto1_1);

    #Test 4: Client falls back from (D)TLSv1.3 (server does not support the
    #        fallback SCSV)
    $proxy->clear();
    $testtype = FALLBACK_FROM_TLS_1_3;
    $proxy->clientflags("-fallback_scsv -max_protocol ".$proto1_2);
    $proxy->start();
    my $alert = TLSProxy::Message->alert();
    ok(TLSProxy::Message->fail()
        && !$alert->server()
        && $alert->description() == TLSProxy::Message::AL_DESC_ILLEGAL_PARAMETER,
        "Fallback from ".$proto1_3);

    SKIP: {
        skip "TLSv1.1 disabled", 2 if disabled("tls1_1");
        skip "Missing support for no_dtls1_2", 2 if $run_test_as_dtls == 1;
        #Test 5: A client side protocol "hole" should not be detected as a downgrade
        $proxy->clear();
        $proxy->filter(undef);
        $proxy->clientflags("-no_tls1_2");
        $proxy->ciphers("AES128-SHA:\@SECLEVEL=0");
        $proxy->start();
        ok(TLSProxy::Message->success(), $proto1_2." client-side protocol hole");

        #Test 6: A server side protocol "hole" should not be detected as a downgrade
        $proxy->clear();
        $proxy->filter(undef);
        $proxy->serverflags("-no_tls1_2");
        $proxy->start();
        ok(TLSProxy::Message->success(), $proto1_2." server-side protocol hole");
    }
}

sub downgrade_filter
{
    my $proxy = shift;

    # We're only interested in the initial ClientHello except if we are expecting
    # DTLS1.2 handshake in which case the client will send a second ClientHello
    my $second_client_hello = $testtype == FALLBACK_FROM_TLS_1_3 && $proxy->isdtls
                              && $proxy->flight == 2;

    if ($proxy->flight != 0 && !$second_client_hello) {
        return;
    }

    my $message;

    if ($second_client_hello == 0) {
        $message = ${$proxy->message_list}[0];
    } else {
        $message = ${$proxy->message_list}[2];
    }

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

        if ($testtype == DOWNGRADE_TO_TLS_1_2) {
            $ext = pack "C3",
                0x02, # Length
                $version12hi, $version12lo;
        } else {
            $ext = pack "C3",
                0x02, # Length
                $version11hi, $version11lo;
        }

        $message->set_extension(TLSProxy::Message::EXT_SUPPORTED_VERSIONS, $ext);
    }

    $message->repack();
}

