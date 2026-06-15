#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;
use TLSProxy::Message;
use Cwd qw(abs_path);

my $test_name = "test_tlpskext";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;
plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");
plan skip_all => "No TLS protocols are supported by this OpenSSL build"
    if alldisabled(available_protocols("tls"));
plan skip_all => "$test_name needs the module feature enabled"
    if disabled("module");
plan skip_all => "$test_name needs the psk feature enabled"
    if disabled("psk");

$ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("test"));

my $psk = "0102030405060708090a0b0c0d0e0f10";

my $proxy = TLSProxy::Proxy->new(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE}),
    have_IPv6()
);

$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";

my $tls13_disabled = disabled("tls1_3") || (disabled("ec") && disabled("dh"));
my $tls12_disabled = disabled("tls1_2");
plan skip_all => "$test_name needs TLSv1.2 or TLSv1.3 enabled"
    if $tls13_disabled && $tls12_disabled;
plan tests => 6;

my $psk_ext_in_ch = 0;
my $psk_ext_in_sh = 0;

SKIP: {
    skip "TLS 1.3 disabled", 4
        if disabled("tls1_3") || (disabled("ec") && disabled("dh"));

    my $flags = "-tls1_3 -no_rx_cert_comp";

    # psk_use_session_cb (client) / psk_find_session_cb (server).
    $proxy->clear();
    $proxy->clientflags("-psk $psk $flags");
    $proxy->serverflags("-psk $psk $flags");
    $proxy->filter(undef);
    $proxy->start();
    ok(TLSProxy::Message->success(), "TLS 1.3 PSK connection");

    $proxy->clear();
    $proxy->clientflags("-psk $psk $flags");
    $proxy->serverflags("-psk $psk $flags");
    $psk_ext_in_ch = 0;
    $proxy->filter(\&check_psk_in_ch);
    $proxy->start();
    ok($psk_ext_in_ch, "PSK extension present in TLS 1.3 ClientHello");

    # psk_find_session_cb returns *sess = NULL on mismatch; falls back to cert.
    $proxy->clear();
    $proxy->clientflags("-psk $psk -psk_identity other_id $flags");
    $proxy->serverflags("-psk $psk $flags");
    $proxy->filter(undef);
    $proxy->start();
    ok(TLSProxy::Message->success(),
       "TLS 1.3 PSK identity mismatch falls back to certificate auth");

    $proxy->clear();
    $proxy->clientflags("-psk $psk -psk_identity other_id $flags");
    $proxy->serverflags("-psk $psk $flags");
    $psk_ext_in_sh = 0;
    $proxy->filter(\&check_psk_in_sh);
    $proxy->start();
    ok(!$psk_ext_in_sh,
       "No PSK in ServerHello when TLS 1.3 identity mismatches");
}

SKIP: {
    skip "TLS 1.2 disabled", 2 if disabled("tls1_2");

    # PSK-AES128-CBC-SHA is required here: TLSProxy's record layer only handles
    # CBC correctly (it strips IV + padding + MAC as fixed offset bytes).
    # GCM ciphers use a different wire layout and confuse the decryption stub,
    # making close_notify detection fail even on a successful connection.
    my $psk_cipher = "PSK-AES128-CBC-SHA:\@SECLEVEL=0";
    my $flags      = "-tls1_2 -no_rx_cert_comp";

    # psk_client_cb (client) / psk_server_cb (server).
    $proxy->clear();
    $proxy->ciphers($psk_cipher);
    $proxy->cipherc($psk_cipher);
    $proxy->clientflags("-psk $psk $flags");
    $proxy->serverflags("-psk $psk $flags");
    $proxy->filter(undef);
    $proxy->start();
    ok(TLSProxy::Message->success(), "TLS 1.2 PSK connection");

    # psk_server_cb accepts regardless of identity and only logs a warning.
    $proxy->clear();
    $proxy->ciphers($psk_cipher);
    $proxy->cipherc($psk_cipher);
    $proxy->clientflags("-psk $psk -psk_identity other_id $flags");
    $proxy->serverflags("-psk $psk $flags");
    $proxy->filter(undef);
    $proxy->start();
    ok(TLSProxy::Message->success(),
       "TLS 1.2 PSK identity mismatch succeeds with warning");
}

sub check_psk_in_ch
{
    my $proxy = shift;

    return if $proxy->flight != 0;

    foreach my $message (@{$proxy->message_list}) {
        next unless $message->mt == TLSProxy::Message::MT_CLIENT_HELLO;
        $psk_ext_in_ch = 1
            if defined ${$message->extension_data}{TLSProxy::Message::EXT_PSK};
    }
}

sub check_psk_in_sh
{
    my $proxy = shift;

    return if $proxy->flight != 1;

    foreach my $message (@{$proxy->message_list}) {
        next unless $message->mt == TLSProxy::Message::MT_SERVER_HELLO;
        $psk_ext_in_sh = 1
            if defined ${$message->extension_data}{TLSProxy::Message::EXT_PSK};
    }
}
