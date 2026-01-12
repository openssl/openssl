#! /usr/bin/env perl
# Copyright 2017-2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file srctop_dir bldtop_dir/;
use OpenSSL::Test::Utils;
use File::Temp qw(tempfile);
use TLSProxy::Proxy;
use Cwd qw(abs_path);

my $test_name = "test_tls13psk";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the module feature enabled"
    if disabled("module");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs elliptic curves or diffie-hellman enabled"
    if disabled("ec") && disabled("dh");

$ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("test"));

my $testcount = 5;

plan tests => 2 * $testcount;

use constant {
    PSK_LAST_FIRST_CH => 0,
    ILLEGAL_EXT_SECOND_CH => 1
};

SKIP: {
    skip "TLS 1.3 is disabled", $testcount if disabled("tls1_3");
    # Run tests with TLS
    run_tests(0);
}

SKIP: {
    skip "DTLS 1.3 is disabled", $testcount if disabled("dtls1_3");
    skip "DTLSProxy does not work on Windows", $testcount if $^O =~ /^(MSWin32)$/;
    run_tests(1);
}

my $testtype = -1;

sub run_tests
{
    my $run_test_as_dtls = shift;
    my $proxy_start_success = 0;

    my $proxy;
    if ($run_test_as_dtls == 1) {
        $proxy = TLSProxy::Proxy->new_dtls(
            undef,
            cmdstr(app([ "openssl" ]), display => 1),
            srctop_file("apps", "server.pem"),
            (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
        );
    }
    else {
        $proxy = TLSProxy::Proxy->new(
            undef,
            cmdstr(app([ "openssl" ]), display => 1),
            srctop_file("apps", "server.pem"),
            (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
        );
    }

    my $curve_list = "-curves P-256:P-384:X25519:X448:ffdhe2048:ffdhe3072";

    if (disabled("ec")) {
        $curve_list = "-curves ffdhe2048:ffdhe3072";
    } elsif (disabled("ecx")) {
        $curve_list = "-curves P-256:P-384:ffdhe2048:ffdhe3072";
    } elsif (disabled("dh")) {
        $curve_list = "-curves P-256:P-384:X25519:X448";
    }

    #Most PSK tests are done in test_ssl_new. This tests various failure scenarios
    #around PSK

    #Test 1: First get a session
    $proxy->clear();
    (undef, my $session) = tempfile();
    $proxy->clientflags($curve_list . " -sess_out " . $session);
    $proxy->serverflags($curve_list . " -servername localhost");
    $proxy->sessionfile($session);
    $proxy_start_success = $proxy->start();
    skip "TLSProxy did not start correctly", $testcount if $proxy_start_success == 0;
    ok(TLSProxy::Message->success(), "Initial connection");

    #Test 2: Attempt a resume with PSK not in last place. Should fail
    $proxy->clear();
    $proxy->clientflags($curve_list . " -sess_in " . $session);
    $proxy->serverflags($curve_list);
    $proxy->filter(\&modify_psk_filter);
    $testtype = PSK_LAST_FIRST_CH;
    $proxy->start();
    ok(TLSProxy::Message->fail(), "PSK not last");

    #Test 3: Attempt a resume after an HRR where PSK hash matches selected
    #        ciphersuite. Should see PSK on second ClientHello
    $proxy->clear();
    $proxy->clientflags($curve_list . " -sess_in " . $session);
    if (disabled("ec")) {
        $proxy->serverflags("-curves ffdhe3072");
    }
    else {
        $proxy->serverflags("-curves P-384");
    }
    $proxy->filter(undef);
    $proxy->start();
    #Check if the PSK is present in the second ClientHello
    my $ch2 = ${$proxy->message_list}[2];
    my $ch2seen = defined $ch2 && $ch2->mt() == TLSProxy::Message::MT_CLIENT_HELLO;
    my $pskseen = $ch2seen
        && defined ${$ch2->{extension_data}}{TLSProxy::Message::EXT_PSK};
    ok($pskseen, "PSK hash matches");

    #Test 4: Attempt a resume after an HRR where PSK hash does not match selected
    #        ciphersuite. Should not see PSK on second ClientHello
    $proxy->clear();
    $proxy->clientflags($curve_list . " -sess_in " . $session);
    $proxy->filter(\&modify_psk_filter);
    if (disabled("ec")) {
        $proxy->serverflags("-curves ffdhe3072");
    }
    else {
        $proxy->serverflags("-curves P-384");
    }
    $proxy->ciphersuitesc("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384");
    $proxy->ciphersuitess("TLS_AES_256_GCM_SHA384");
    #We force an early failure because TLS Proxy doesn't actually support
    #TLS_AES_256_GCM_SHA384. That doesn't matter for this test though.
    $testtype = ILLEGAL_EXT_SECOND_CH;
    $proxy->start();
    #Check if the PSK is present in the second ClientHello
    $ch2 = ${$proxy->message_list}[2];
    $ch2seen = defined $ch2 && $ch2->mt() == TLSProxy::Message::MT_CLIENT_HELLO;
    $pskseen = $ch2seen
        && defined ${$ch2->extension_data}{TLSProxy::Message::EXT_PSK};
    ok($ch2seen && !$pskseen, "PSK hash does not match");

    #Test 5: Attempt a resume without a sig agls extension. Should succeed because
    #        sig algs is not needed in a resumption.
    $proxy->clear();
    $proxy->clientflags($curve_list . " -sess_in " . $session);
    $proxy->serverflags($curve_list);
    $proxy->filter(\&remove_sig_algs_filter);
    $proxy->start();
    ok(TLSProxy::Message->success(), "Remove sig algs");

    unlink $session;
}

sub modify_psk_filter
{
    my $proxy = shift;
    my $flight;
    my $message;

    if ($testtype == PSK_LAST_FIRST_CH) {
        $flight = 0;
    } else {
        $flight = 2;
    }

    # Only look at the first or second ClientHello
    return if $proxy->flight != $flight;

    if ($testtype == PSK_LAST_FIRST_CH) {
        $message = ${$proxy->message_list}[0];
    } else {
        $message = ${$proxy->message_list}[2];
    }

    return if (!defined $message
               || $message->mt != TLSProxy::Message::MT_CLIENT_HELLO);

    if ($testtype == PSK_LAST_FIRST_CH) {
        $message->set_extension(TLSProxy::Message::EXT_FORCE_LAST, "");
    } else {
        #Deliberately break the connection
        $message->set_extension(TLSProxy::Message::EXT_SUPPORTED_GROUPS, "");
    }
    $message->repack();
}

sub remove_sig_algs_filter
{
    my $proxy = shift;
    my $message;

    # Only look at the first ClientHello
    return if $proxy->flight != 0;

    $message = ${$proxy->message_list}[0];
    $message->delete_extension(TLSProxy::Message::EXT_SIG_ALGS);
    $message->repack();
}
