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

plan tests => 2;

# Test 1: RFC 8446 Section 4.2.9 - psk_dhe_ke requires key_share
# Remove key_share and supported_groups, keep psk_key_exchange_modes
# This isolates the first validation check in final_key_share() in extensions.c
$proxy->filter(\&remove_keyshare_and_groups_filter);
$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
ok(TLSProxy::Message->fail(), "Test 1: psk_dhe_ke without key_share should fail (RFC 8446 4.2.9)");

# Test 2: RFC 8446 Section 9.2 - supported_groups requires key_share
# Remove key_share and psk_key_exchange_modes, keep supported_groups
# This isolates the second validation check in final_key_share in extensions.c
$proxy->clear();
$proxy->filter(\&remove_keyshare_and_psk_modes_filter);
$proxy->start();
ok(TLSProxy::Message->fail(), "Test 2: supported_groups without key_share should fail (RFC 8446 9.2)");

sub remove_keyshare_and_groups_filter
{
    my $proxy = shift;

    # Only interested in the initial ClientHello
    return if $proxy->flight != 0;

    foreach my $message (@{$proxy->message_list}) {
        if ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO) {
            # Remove key_share and supported_groups
            # Keep psk_key_exchange_modes (which includes psk_dhe_ke)
            # This triggers: extensions.c:1398 - psk_dhe_ke requires key_share
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
            # This triggers: extensions.c:1409 - supported_groups requires key_share
            $message->delete_extension(TLSProxy::Message::EXT_KEY_SHARE);
            $message->delete_extension(TLSProxy::Message::EXT_PSK_KEX_MODES);
            $message->repack();
        }
    }
}
