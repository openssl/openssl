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
use Cwd qw(abs_path);

my $test_name = "test_tls13keyshare";
setup($test_name);

$ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("test"));

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the module feature enabled"
    if disabled("module");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs TLS1.3 enabled"
    if disabled("tls1_3") || (disabled("ec") && disabled("dh"));

my $proxy = TLSProxy::Proxy->new(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

plan tests => 6;

# Test 1: RFC 8446 Section 4.2.9 - psk_dhe_ke requires key_share (Issue #25124)
# Initial ClientHello: Remove key_share and supported_groups, keep psk_key_exchange_modes
# This isolates the first validation check in final_key_share() in extensions.c
$proxy->filter(\&remove_keyshare_and_groups_filter);
$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
ok(TLSProxy::Message->fail(), "Test 1: Initial CH - psk_dhe_ke without key_share should fail (RFC 8446 4.2.9)");

# Test 2: RFC 8446 Section 4.2.9 - HRR scenario
# Second ClientHello after HRR: Remove key_share and supported_groups, keep psk_key_exchange_modes
SKIP: {
    skip "EC is disabled in this build", 1 if disabled("ec");

    $proxy->clear();
    $proxy->clientflags("-groups P-256:P-384");
    $proxy->serverflags("-groups P-384");
    $proxy->filter(\&remove_keyshare_and_groups_in_hrr_filter);
    $proxy->start();
    ok(TLSProxy::Message->fail(), "Test 2: HRR - psk_dhe_ke without key_share should fail (RFC 8446 4.2.9)");
}

# Test 3: RFC 8446 Section 9.2 - supported_groups requires key_share (Issue #25124)
# Initial ClientHello: Remove key_share and psk_key_exchange_modes, keep supported_groups
# This isolates the second validation check in final_key_share in extensions.c
$proxy->clear();
$proxy->filter(\&remove_keyshare_and_psk_modes_filter);
$proxy->start();
ok(TLSProxy::Message->fail(), "Test 3: Initial CH - supported_groups without key_share should fail (RFC 8446 9.2)");

# Test 4: RFC 8446 Section 9.2 - HRR scenario
# Second ClientHello after HRR: Remove key_share and psk_key_exchange_modes, keep supported_groups
SKIP: {
    skip "EC is disabled in this build", 1 if disabled("ec");

    $proxy->clear();
    $proxy->clientflags("-groups P-256:P-384");
    $proxy->serverflags("-groups P-384");
    $proxy->filter(\&remove_keyshare_and_psk_modes_in_hrr_filter);
    $proxy->start();
    ok(TLSProxy::Message->fail(), "Test 4: HRR - supported_groups without key_share should fail (RFC 8446 9.2)");
}

# Test 5: RFC 8446 Section 9.2 (reverse) - key_share requires supported_groups (Issue #25124)
# Initial ClientHello: Remove supported_groups and psk_key_exchange_modes, keep key_share
# This isolates the third validation check in final_key_share in extensions.c
$proxy->clear();
$proxy->filter(\&remove_groups_and_psk_modes_filter);
$proxy->start();
ok(TLSProxy::Message->fail(), "Test 5: Initial CH - key_share without supported_groups should fail (RFC 8446 9.2)");

# Test 6: RFC 8446 Section 9.2 (reverse) - HRR scenario (Issue #25038)
# Trigger HRR, then in second ClientHello remove supported_groups but keep key_share
# This validates the fix works in the HRR context
SKIP: {
    skip "EC is disabled in this build", 1 if disabled("ec");

    $proxy->clear();
    # Force HRR by having server prefer a different group
    $proxy->clientflags("-groups P-256:P-384");
    $proxy->serverflags("-groups P-384");
    $proxy->filter(\&remove_groups_and_psk_modes_in_hrr_filter);
    $proxy->start();
    ok(TLSProxy::Message->fail(), "Test 6: HRR - key_share without supported_groups should fail (RFC 8446 9.2)");
}

sub remove_keyshare_and_groups_filter
{
    my $proxy = shift;

    # Only interested in the initial ClientHello
    return if $proxy->flight != 0;

    foreach my $message (@{$proxy->message_list}) {
        if ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO) {
            # Remove key_share and supported_groups
            # Keep psk_key_exchange_modes (which includes psk_dhe_ke)
            $message->delete_extension(TLSProxy::Message::EXT_KEY_SHARE);
            $message->delete_extension(TLSProxy::Message::EXT_SUPPORTED_GROUPS);
            $message->repack();
        }
    }
}

sub remove_keyshare_and_psk_modes_filter
{
    my $proxy = shift;

    # Only interested in the initial ClientHello
    return if $proxy->flight != 0;

    foreach my $message (@{$proxy->message_list}) {
        if ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO) {
            # Remove key_share and psk_key_exchange_modes
            # Keep supported_groups
            $message->delete_extension(TLSProxy::Message::EXT_KEY_SHARE);
            $message->delete_extension(TLSProxy::Message::EXT_PSK_KEX_MODES);
            $message->repack();
        }
    }
}

sub remove_groups_and_psk_modes_filter
{
    my $proxy = shift;

    # Only interested in the initial ClientHello
    return if $proxy->flight != 0;

    foreach my $message (@{$proxy->message_list}) {
        if ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO) {
            # Remove supported_groups and psk_key_exchange_modes
            # Keep key_share
            $message->delete_extension(TLSProxy::Message::EXT_SUPPORTED_GROUPS);
            $message->delete_extension(TLSProxy::Message::EXT_PSK_KEX_MODES);
            $message->repack();
        }
    }
}

sub remove_keyshare_and_groups_in_hrr_filter
{
    my $proxy = shift;

    # Only interested in the second ClientHello (after HRR)
    return if $proxy->flight != 2;

    foreach my $message (@{$proxy->message_list}) {
        if ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO) {
            # Remove key_share and supported_groups from second ClientHello
            # Keep psk_key_exchange_modes
            $message->delete_extension(TLSProxy::Message::EXT_KEY_SHARE);
            $message->delete_extension(TLSProxy::Message::EXT_SUPPORTED_GROUPS);
            $message->repack();
        }
    }
}

sub remove_keyshare_and_psk_modes_in_hrr_filter
{
    my $proxy = shift;

    # Only interested in the second ClientHello (after HRR)
    return if $proxy->flight != 2;

    foreach my $message (@{$proxy->message_list}) {
        if ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO) {
            # Remove key_share and psk_key_exchange_modes from second ClientHello
            # Keep supported_groups
            $message->delete_extension(TLSProxy::Message::EXT_KEY_SHARE);
            $message->delete_extension(TLSProxy::Message::EXT_PSK_KEX_MODES);
            $message->repack();
        }
    }
}

sub remove_groups_and_psk_modes_in_hrr_filter
{
    my $proxy = shift;

    # Only interested in the second ClientHello (after HRR)
    return if $proxy->flight != 2;

    foreach my $message (@{$proxy->message_list}) {
        if ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO) {
            # Remove supported_groups and psk_key_exchange_modes from second ClientHello
            # Keep key_share
            $message->delete_extension(TLSProxy::Message::EXT_SUPPORTED_GROUPS);
            $message->delete_extension(TLSProxy::Message::EXT_PSK_KEX_MODES);
            $message->repack();
        }
    }
}
