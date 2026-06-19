#! /usr/bin/env perl
# Copyright 2015-2026 The OpenSSL Project Authors. All Rights Reserved.
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
use checkhandshake qw(checkhandshake @handmessages @extensions);
use Cwd qw(abs_path);

my $test_name = "test_tls13messages";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the module feature enabled"
    if disabled("module");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs EC enabled"
    if disabled("ec");

@handmessages = (
    [TLSProxy::Message::MT_CLIENT_HELLO,
        checkhandshake::ALL_HANDSHAKES],
    [TLSProxy::Message::MT_SERVER_HELLO,
        checkhandshake::HRR_HANDSHAKE | checkhandshake::HRR_RESUME_HANDSHAKE],
    [TLSProxy::Message::MT_CLIENT_HELLO,
        checkhandshake::HRR_HANDSHAKE | checkhandshake::HRR_RESUME_HANDSHAKE],
    [TLSProxy::Message::MT_SERVER_HELLO,
        checkhandshake::ALL_HANDSHAKES],
    [TLSProxy::Message::MT_ENCRYPTED_EXTENSIONS,
        checkhandshake::ALL_HANDSHAKES],
    [TLSProxy::Message::MT_CERTIFICATE_REQUEST,
        checkhandshake::CLIENT_AUTH_HANDSHAKE],
    [TLSProxy::Message::MT_CERTIFICATE,
        checkhandshake::ALL_HANDSHAKES & ~(checkhandshake::RESUME_HANDSHAKE | checkhandshake::HRR_RESUME_HANDSHAKE)],
    [TLSProxy::Message::MT_CERTIFICATE_VERIFY,
        checkhandshake::ALL_HANDSHAKES & ~(checkhandshake::RESUME_HANDSHAKE | checkhandshake::HRR_RESUME_HANDSHAKE)],
    [TLSProxy::Message::MT_FINISHED,
        checkhandshake::ALL_HANDSHAKES],
    [TLSProxy::Message::MT_CERTIFICATE,
        checkhandshake::CLIENT_AUTH_HANDSHAKE],
    [TLSProxy::Message::MT_CERTIFICATE_VERIFY,
        checkhandshake::CLIENT_AUTH_HANDSHAKE],
    [TLSProxy::Message::MT_FINISHED,
        checkhandshake::ALL_HANDSHAKES],
    [0, 0]
);

@extensions = (
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SERVER_NAME,
        TLSProxy::Message::CLIENT,
        checkhandshake::SERVER_NAME_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_STATUS_REQUEST,
        TLSProxy::Message::CLIENT,
        checkhandshake::STATUS_REQUEST_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SUPPORTED_GROUPS,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_EC_POINT_FORMATS,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SIG_ALGS,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_ALPN,
        TLSProxy::Message::CLIENT,
        checkhandshake::ALPN_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SCT,
        TLSProxy::Message::CLIENT,
        checkhandshake::SCT_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_ENCRYPT_THEN_MAC,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_EXTENDED_MASTER_SECRET,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SESSION_TICKET,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_KEY_SHARE,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SUPPORTED_VERSIONS,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_PSK_KEX_MODES,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_PSK,
        TLSProxy::Message::CLIENT,
        checkhandshake::PSK_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_POST_HANDSHAKE_AUTH,
        TLSProxy::Message::CLIENT,
        checkhandshake::POST_HANDSHAKE_AUTH_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_RENEGOTIATE,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],

    [TLSProxy::Message::MT_SERVER_HELLO, TLSProxy::Message::EXT_SUPPORTED_VERSIONS,
        TLSProxy::Message::SERVER,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_SERVER_HELLO, TLSProxy::Message::EXT_KEY_SHARE,
        TLSProxy::Message::SERVER,
        checkhandshake::KEY_SHARE_HRR_EXTENSION],

    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SERVER_NAME,
        TLSProxy::Message::CLIENT,
        checkhandshake::SERVER_NAME_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_STATUS_REQUEST,
        TLSProxy::Message::CLIENT,
        checkhandshake::STATUS_REQUEST_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SUPPORTED_GROUPS,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_EC_POINT_FORMATS,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SIG_ALGS,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_ALPN,
        TLSProxy::Message::CLIENT,
        checkhandshake::ALPN_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SCT,
        TLSProxy::Message::CLIENT,
        checkhandshake::SCT_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_ENCRYPT_THEN_MAC,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_EXTENDED_MASTER_SECRET,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SESSION_TICKET,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_KEY_SHARE,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SUPPORTED_VERSIONS,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_PSK_KEX_MODES,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_PSK,
        TLSProxy::Message::CLIENT,
        checkhandshake::PSK_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_POST_HANDSHAKE_AUTH,
        TLSProxy::Message::CLIENT,
        checkhandshake::POST_HANDSHAKE_AUTH_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_RENEGOTIATE,
        TLSProxy::Message::CLIENT,
        checkhandshake::DEFAULT_EXTENSIONS],

    [TLSProxy::Message::MT_SERVER_HELLO, TLSProxy::Message::EXT_SUPPORTED_VERSIONS,
        TLSProxy::Message::SERVER,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_SERVER_HELLO, TLSProxy::Message::EXT_KEY_SHARE,
        TLSProxy::Message::SERVER,
        checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_SERVER_HELLO, TLSProxy::Message::EXT_PSK,
        TLSProxy::Message::SERVER,
        checkhandshake::PSK_SRV_EXTENSION],

    [TLSProxy::Message::MT_ENCRYPTED_EXTENSIONS, TLSProxy::Message::EXT_SERVER_NAME,
        TLSProxy::Message::SERVER,
        checkhandshake::SERVER_NAME_SRV_EXTENSION],
    [TLSProxy::Message::MT_ENCRYPTED_EXTENSIONS, TLSProxy::Message::EXT_ALPN,
        TLSProxy::Message::SERVER,
        checkhandshake::ALPN_SRV_EXTENSION],
    [TLSProxy::Message::MT_ENCRYPTED_EXTENSIONS, TLSProxy::Message::EXT_SUPPORTED_GROUPS,
        TLSProxy::Message::SERVER,
        checkhandshake::SUPPORTED_GROUPS_SRV_EXTENSION],

    [TLSProxy::Message::MT_CERTIFICATE_REQUEST, TLSProxy::Message::EXT_SIG_ALGS,
        TLSProxy::Message::SERVER,
        checkhandshake::DEFAULT_EXTENSIONS],

    [TLSProxy::Message::MT_CERTIFICATE, TLSProxy::Message::EXT_STATUS_REQUEST,
        TLSProxy::Message::SERVER,
        checkhandshake::STATUS_REQUEST_SRV_EXTENSION],
    [TLSProxy::Message::MT_CERTIFICATE, TLSProxy::Message::EXT_SCT,
        TLSProxy::Message::SERVER,
        checkhandshake::SCT_SRV_EXTENSION],

    [0,0,0,0]
);

$ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("test"));

my $testcount = 19;
my $fatal_alert = 0;
my $hello_request_added = 0;
my $hello_request_after_server_hello = 0;
my $hello_request_record_epoch = -1;
my $hello_request_record_seq = -1;

plan tests => 2 * $testcount;

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

sub run_tests
{
    my $run_test_as_dtls = shift;
    my $proxy_start_success = 0;

    (undef, my $session) = tempfile();
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

    $proxy->clear();

    #Test 1: Check we get all the right messages for a default handshake
    $proxy->serverconnects(2);
    $proxy->cipherc("DEFAULT:\@SECLEVEL=2");
    $proxy->clientflags("-no_rx_cert_comp -sess_out " . $session);
    $proxy->sessionfile($session);
    $proxy_start_success = $proxy->start();
    skip "TLSProxy did not start correctly", $testcount if $proxy_start_success == 0;
    checkhandshake($proxy, checkhandshake::DEFAULT_HANDSHAKE,
        checkhandshake::DEFAULT_EXTENSIONS,
        "Default handshake test");

    #Test 2: Resumption handshake
    $proxy->clearClient();
    $proxy->cipherc("DEFAULT:\@SECLEVEL=2");
    $proxy->clientflags("-no_rx_cert_comp -sess_in " . $session);
    $proxy->clientstart();
    checkhandshake($proxy, checkhandshake::RESUME_HANDSHAKE,
        (checkhandshake::DEFAULT_EXTENSIONS
            | checkhandshake::PSK_CLI_EXTENSION
            | checkhandshake::PSK_SRV_EXTENSION),
        "Resumption handshake test");


    SKIP: {
        skip "No OCSP support in this OpenSSL build", 4
            if disabled("ct") || disabled("ec") || disabled("ocsp");
        #Test 3: A status_request handshake (client request only)
        $proxy->clear();
        $proxy->cipherc("DEFAULT:\@SECLEVEL=2");
        $proxy->clientflags("-no_rx_cert_comp -status");
        $proxy_start_success = $proxy->start();
        skip "TLSProxy did not start correctly", 4 if $proxy_start_success == 0;
        checkhandshake($proxy, checkhandshake::DEFAULT_HANDSHAKE,
            checkhandshake::DEFAULT_EXTENSIONS
                | checkhandshake::STATUS_REQUEST_CLI_EXTENSION,
            "status_request handshake test (client)");

        #Test 4: A status_request handshake (server support only)
        $proxy->clear();
        $proxy->cipherc("DEFAULT:\@SECLEVEL=2");
        $proxy->clientflags("-no_rx_cert_comp");
        $proxy->serverflags("-no_rx_cert_comp -status_file "
            . srctop_file("test", "recipes", "ocsp-response.der"));
        $proxy->start();
        checkhandshake($proxy, checkhandshake::DEFAULT_HANDSHAKE,
            checkhandshake::DEFAULT_EXTENSIONS,
            "status_request handshake test (server)");

        #Test 5: A status_request handshake (client and server)
        $proxy->clear();
        $proxy->cipherc("DEFAULT:\@SECLEVEL=2");
        $proxy->clientflags("-no_rx_cert_comp -status");
        $proxy->serverflags("-no_rx_cert_comp -status_file "
            . srctop_file("test", "recipes", "ocsp-response.der"));
        $proxy->start();
        checkhandshake($proxy, checkhandshake::DEFAULT_HANDSHAKE,
            checkhandshake::DEFAULT_EXTENSIONS
                | checkhandshake::STATUS_REQUEST_CLI_EXTENSION
                | checkhandshake::STATUS_REQUEST_SRV_EXTENSION,
            "status_request handshake test");

        #Test 6: A status_request handshake (client and server) with client auth
        $proxy->clear();
        $proxy->cipherc("DEFAULT:\@SECLEVEL=2");
        $proxy->clientflags("-no_rx_cert_comp -status -enable_pha -cert "
            . srctop_file("apps", "server.pem"));
        $proxy->serverflags("-no_rx_cert_comp -Verify 5 -status_file "
            . srctop_file("test", "recipes", "ocsp-response.der"));
        $proxy->start();
        checkhandshake($proxy, checkhandshake::CLIENT_AUTH_HANDSHAKE,
            checkhandshake::DEFAULT_EXTENSIONS
                | checkhandshake::STATUS_REQUEST_CLI_EXTENSION
                | checkhandshake::STATUS_REQUEST_SRV_EXTENSION
                | checkhandshake::POST_HANDSHAKE_AUTH_CLI_EXTENSION,
            "status_request handshake with client auth test");
    }

    #Test 7: A client auth handshake
    $proxy->clear();
    $proxy->cipherc("DEFAULT:\@SECLEVEL=2");
    $proxy->clientflags("-no_rx_cert_comp -enable_pha"
                        ." -cert ".srctop_file("apps", "server.pem"));
    $proxy->serverflags("-no_rx_cert_comp -Verify 5");
    $proxy_start_success = $proxy->start();
    skip "TLSProxy did not start correctly", $testcount - 6 if $proxy_start_success == 0;
    checkhandshake($proxy, checkhandshake::CLIENT_AUTH_HANDSHAKE,
                   checkhandshake::DEFAULT_EXTENSIONS
                   | checkhandshake::POST_HANDSHAKE_AUTH_CLI_EXTENSION,
                   "Client auth handshake test");

    #Test 8: Server name handshake (no client request)
    $proxy->clear();
    $proxy->cipherc("DEFAULT:\@SECLEVEL=2");
    $proxy->clientflags("-no_rx_cert_comp -noservername");
    $proxy->start();
    checkhandshake($proxy, checkhandshake::DEFAULT_HANDSHAKE,
        checkhandshake::DEFAULT_EXTENSIONS
            & ~checkhandshake::SERVER_NAME_CLI_EXTENSION,
        "Server name handshake test (client)");

    #Test 9: Server name handshake (server support only)
    $proxy->clear();
    $proxy->cipherc("DEFAULT:\@SECLEVEL=2");
    $proxy->clientflags("-no_rx_cert_comp -noservername");
    $proxy->serverflags("-no_rx_cert_comp -servername testhost");
    $proxy->start();
    checkhandshake($proxy, checkhandshake::DEFAULT_HANDSHAKE,
        checkhandshake::DEFAULT_EXTENSIONS
            & ~checkhandshake::SERVER_NAME_CLI_EXTENSION,
        "Server name handshake test (server)");

    #Test 10: Server name handshake (client and server)
    $proxy->clear();
    $proxy->cipherc("DEFAULT:\@SECLEVEL=2");
    $proxy->clientflags("-no_rx_cert_comp -servername testhost");
    $proxy->serverflags("-no_rx_cert_comp -servername testhost");
    $proxy->start();
    checkhandshake($proxy, checkhandshake::DEFAULT_HANDSHAKE,
        checkhandshake::DEFAULT_EXTENSIONS
            | checkhandshake::SERVER_NAME_SRV_EXTENSION,
        "Server name handshake test");

    #Test 11: ALPN handshake (client request only)
    $proxy->clear();
    $proxy->cipherc("DEFAULT:\@SECLEVEL=2");
    $proxy->clientflags("-no_rx_cert_comp -alpn test");
    $proxy->start();
    checkhandshake($proxy, checkhandshake::DEFAULT_HANDSHAKE,
        checkhandshake::DEFAULT_EXTENSIONS
            | checkhandshake::ALPN_CLI_EXTENSION,
        "ALPN handshake test (client)");

    #Test 12: ALPN handshake (server support only)
    $proxy->clear();
    $proxy->cipherc("DEFAULT:\@SECLEVEL=2");
    $proxy->clientflags("-no_rx_cert_comp");
    $proxy->serverflags("-no_rx_cert_comp -alpn test");
    $proxy->start();
    checkhandshake($proxy, checkhandshake::DEFAULT_HANDSHAKE,
        checkhandshake::DEFAULT_EXTENSIONS,
        "ALPN handshake test (server)");

    #Test 13: ALPN handshake (client and server)
    $proxy->clear();
    $proxy->cipherc("DEFAULT:\@SECLEVEL=2");
    $proxy->clientflags("-no_rx_cert_comp -alpn test");
    $proxy->serverflags("-no_rx_cert_comp -alpn test");
    $proxy->start();
    checkhandshake($proxy, checkhandshake::DEFAULT_HANDSHAKE,
        checkhandshake::DEFAULT_EXTENSIONS
            | checkhandshake::ALPN_CLI_EXTENSION
            | checkhandshake::ALPN_SRV_EXTENSION,
        "ALPN handshake test");

    SKIP: {
        skip "No CT, EC or OCSP support in this OpenSSL build", 1
            if disabled("ct") || disabled("ec") || disabled("ocsp");

        #Test 14: SCT handshake (client request only)
        $proxy->clear();
        $proxy->cipherc("DEFAULT:\@SECLEVEL=2");
        #Note: -ct also sends status_request
        $proxy->clientflags("-no_rx_cert_comp -ct");
        $proxy->serverflags("-no_rx_cert_comp -status_file "
            . srctop_file("test", "recipes", "ocsp-response.der")
            . " -serverinfo " . srctop_file("test", "serverinfo2.pem"));
        $proxy->start();
        checkhandshake($proxy, checkhandshake::DEFAULT_HANDSHAKE,
            checkhandshake::DEFAULT_EXTENSIONS
                | checkhandshake::SCT_CLI_EXTENSION
                | checkhandshake::SCT_SRV_EXTENSION
                | checkhandshake::STATUS_REQUEST_CLI_EXTENSION
                | checkhandshake::STATUS_REQUEST_SRV_EXTENSION,
            "SCT handshake test");
    }

    #Test 15: HRR Handshake
    $proxy->clear();
    $proxy->cipherc("DEFAULT:\@SECLEVEL=2");
    $proxy->clientflags("-no_rx_cert_comp");
    $proxy->serverflags("-no_rx_cert_comp -curves P-384");
    $proxy->start();
    checkhandshake($proxy, checkhandshake::HRR_HANDSHAKE,
        checkhandshake::DEFAULT_EXTENSIONS
            | checkhandshake::KEY_SHARE_HRR_EXTENSION,
        "HRR handshake test");


    #Test 16: Resumption handshake with HRR
    $proxy->clear();
    $proxy->cipherc("DEFAULT:\@SECLEVEL=2");
    $proxy->clientflags("-no_rx_cert_comp -sess_in " . $session);
    $proxy->serverflags("-no_rx_cert_comp -curves P-384");
    $proxy->start();
    checkhandshake($proxy, checkhandshake::HRR_RESUME_HANDSHAKE,
        (checkhandshake::DEFAULT_EXTENSIONS
            | checkhandshake::KEY_SHARE_HRR_EXTENSION
            | checkhandshake::PSK_CLI_EXTENSION
            | checkhandshake::PSK_SRV_EXTENSION),
        "Resumption handshake with HRR test");

    #Test 17: Acceptable but non preferred key_share
    $proxy->clear();
    $proxy->cipherc("DEFAULT:\@SECLEVEL=2");
    $proxy->clientflags("-no_rx_cert_comp -curves P-384");
    $proxy->start();
    checkhandshake($proxy, checkhandshake::DEFAULT_HANDSHAKE,
                   checkhandshake::DEFAULT_EXTENSIONS
                   | checkhandshake::SUPPORTED_GROUPS_SRV_EXTENSION,
                    "Acceptable but non preferred key_share");

    #Test 18: HelloRequest is reserved in (D)TLSv1.3
    $proxy->clear();
    $fatal_alert = 0;
    $hello_request_added = 0;
    $hello_request_after_server_hello = 0;
    $hello_request_record_epoch = -1;
    $hello_request_record_seq = -1;
    $proxy->filter(\&inject_hello_request);
    $proxy->cipherc("DEFAULT:\@SECLEVEL=2");
    if ($run_test_as_dtls) {
        $proxy->clientflags("-no_rx_cert_comp -mtu 16384");
        $proxy->serverflags("-timeout -mtu 16384");
    } else {
        $proxy->clientflags("-no_rx_cert_comp");
    }
    $proxy->start();
    ok($fatal_alert, "HelloRequest rejected in "
       . ($run_test_as_dtls ? "DTLSv1.3" : "TLSv1.3"));

    #Test 19: A HelloRequest received after selecting (D)TLSv1.2 in the initial
    #         handshake is still ignored, confirming the legacy skip path is
    #         preserved even when (D)TLSv1.3 was initially enabled.
    SKIP: {
        my $legacy_version = $run_test_as_dtls ? "DTLSv1.2" : "TLSv1.2";
        my $legacy_version_disabled = $run_test_as_dtls
                                      ? disabled("dtls1_2")
                                      : disabled("tls1_2");

        skip "$legacy_version disabled", 1 if $legacy_version_disabled;

        $proxy->clear();
        $fatal_alert = 0;
        $hello_request_added = 0;
        $hello_request_after_server_hello = 1;
        $hello_request_record_epoch = -1;
        $hello_request_record_seq = -1;
        $proxy->filter(\&inject_hello_request);
        $proxy->cipherc("DEFAULT:\@SECLEVEL=2");
        if ($run_test_as_dtls) {
            $proxy->clientflags("-no_rx_cert_comp -mtu 16384");
            $proxy->serverflags("-max_protocol DTLSv1.2 -mtu 16384");
        } else {
            $proxy->clientflags("-no_rx_cert_comp");
            $proxy->serverflags("-no_tls1_3");
        }
        $proxy->start();
        ok(TLSProxy::Message->success() && !$fatal_alert,
           "HelloRequest ignored in $legacy_version");
    }

    unlink $session;
}

sub inject_hello_request
{
    my $proxy = shift;
    my $records = $proxy->record_list;
    my $hello_request;
    my $record;
    my $server_hello;
    my $server_hello_record;
    my $record_epoch;
    my $record_seq;
    my $record_version;
    my $target_message;
    my $target_record;
    my $msgseq;
    my $i;

    if ($hello_request_added) {
        if ($proxy->isdtls()) {
            foreach my $existing_record (@{$records}) {
                next if $existing_record->{sent};
                next if !$existing_record->serverissender;
                next if $existing_record->epoch != $hello_request_record_epoch;
                next if $existing_record->seq < $hello_request_record_seq;

                $existing_record->seq($existing_record->seq + 1);
            }

            foreach my $existing_record (reverse @{$records}) {
                if ($existing_record->is_fatal_alert(0)
                    == TLSProxy::Message::AL_DESC_UNEXPECTED_MESSAGE) {
                    $fatal_alert = 1;
                    last;
                }
            }
        } elsif (@{$records}[-1]->is_fatal_alert(0)
                 == TLSProxy::Message::AL_DESC_UNEXPECTED_MESSAGE) {
            $fatal_alert = 1;
        }
        return;
    }

    if (!$proxy->isdtls()) {
        return if $proxy->flight != 1;

        $hello_request = pack("C4", TLSProxy::Message::MT_HELLO_REQUEST,
                              0, 0, 0);
        $record = TLSProxy::Record->new(
            1,
            $proxy->flight,
            TLSProxy::Record::RT_HANDSHAKE,
            TLSProxy::Record::VERS_TLS_1_2,
            length($hello_request),
            0,
            length($hello_request),
            length($hello_request),
            $hello_request,
            $hello_request
        );

        if ($hello_request_after_server_hello) {
            foreach my $message (@{$proxy->message_list}) {
                next if $message->mt != TLSProxy::Message::MT_SERVER_HELLO
                        || ${$message->records}[0]->flight != 1;

                $server_hello_record = @{$message->records}[-1];
                last;
            }

            return if !defined $server_hello_record;

            for ($i = 0; $i < @{$records}; $i++) {
                last if ${$records}[$i] == $server_hello_record;
            }
            $i++;
        } else {
            for ($i = 0; ${$records}[$i]->flight() < 1; $i++) {
                next;
            }
        }

        splice @{$records}, $i, 0, $record;
        $hello_request_added = 1;
        return;
    }

    # Insert a standalone server record into an existing DTLS flight, bumping
    # later same-epoch record sequence numbers while preserving handshake message
    # sequences for the expected DTLSv1.3 reject and DTLSv1.2 skip paths.
    if ($hello_request_after_server_hello) {
        return if ($proxy->flight & 1) == 0;

        foreach my $message (@{$proxy->message_list}) {
            next if $message->mt != TLSProxy::Message::MT_SERVER_HELLO
                    || !$message->server;

            $server_hello = $message;
            $server_hello_record = @{$message->records}[-1];
            last;
        }

        return if !defined $server_hello_record;

        for ($i = 0; $i < @{$records}; $i++) {
            last if ${$records}[$i] == $server_hello_record;
        }

        $i++;
        $record_epoch = $server_hello_record->epoch;
        $record_seq = $server_hello_record->seq + 1;
        $record_version = $server_hello_record->version;
        $msgseq = $server_hello->msgseq + 1;
    } else {
        return if $proxy->flight != 1;

        foreach my $message (@{$proxy->message_list}) {
            next if !$message->server
                    || ${$message->records}[0]->flight != $proxy->flight;

            $target_message = $message;
            $target_record = ${$message->records}[0];
            last;
        }

        return if !defined $target_record;

        for ($i = 0; $i < @{$records}; $i++) {
            last if ${$records}[$i] == $target_record;
        }

        $record_epoch = $target_record->epoch;
        $record_seq = $target_record->seq;
        $record_version = $target_record->version;
        $msgseq = $target_message->msgseq;
    }

    foreach my $existing_record (@{$records}) {
        next if !$existing_record->serverissender;
        next if $existing_record->epoch != $record_epoch;
        next if $existing_record->seq < $record_seq;

        $existing_record->seq($existing_record->seq + 1);
    }

    $hello_request = pack("C", TLSProxy::Message::MT_HELLO_REQUEST)
                     . pack("C3", 0, 0, 0)
                     . pack("n", $msgseq)
                     . pack("C3", 0, 0, 0)
                     . pack("C3", 0, 0, 0);
    $record = TLSProxy::Record->new_dtls(
        1,
        $proxy->flight,
        TLSProxy::Record::RT_HANDSHAKE,
        $record_version,
        $record_epoch,
        $record_seq,
        length($hello_request),
        0,
        length($hello_request),
        length($hello_request),
        $hello_request,
        $hello_request
    );

    splice @{$records}, $i, 0, $record;
    $hello_request_added = 1;
    $hello_request_record_epoch = $record_epoch;
    $hello_request_record_seq = $record_seq;
}
