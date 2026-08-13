#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
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

my $test_name = "test_tls13legacyversion";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the module feature enabled"
    if disabled("module");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs TLS1.3 enabled"
    if disabled("tls1_3") || (disabled("ec") && disabled("dh"));

$ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("test"));

my $proxy = TLSProxy::Proxy->new(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE}),
    have_IPv6()
);

#The legacy_version to write into the ServerHello, or undef to leave the
#message alone.
my $legacy_version;

#Test 1: An unmodified handshake still succeeds
$proxy->filter(\&legacy_version_filter);
$legacy_version = undef;
$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
plan tests => 4;
ok(TLSProxy::Message->success(), "Unmodified legacy_version");

#Test 2: RFC 9846 section 4.2.3 - a TLS1.3 ServerHello carrying 0x0304 in
#        legacy_version must be rejected with a protocol_version alert
$proxy->clear();
$legacy_version = TLSProxy::Record::VERS_TLS_1_3;
$proxy->start();
ok(is_protocol_version_client_alert(), "legacy_version of TLSv1.3");

#Test 3: The same for a legacy_version below 0x0303
$proxy->clear();
$legacy_version = TLSProxy::Record::VERS_TLS_1_0;
$proxy->start();
ok(is_protocol_version_client_alert(), "legacy_version of TLSv1.0");

#Test 4: A HelloRetryRequest is a TLS1.3 ServerHello, so the same applies.
#        Force one by offering a group the server does not accept.
$proxy->clear();
if (disabled("ec")) {
    $proxy->serverflags("-curves ffdhe3072");
} else {
    $proxy->serverflags("-curves P-384");
}
$legacy_version = TLSProxy::Record::VERS_TLS_1_3;
$proxy->start();
ok(is_protocol_version_client_alert(),
   "legacy_version of TLSv1.3 in a HelloRetryRequest");

#Validate that the handshake failed with a protocol_version alert sent by
#the client
sub is_protocol_version_client_alert
{
    return 0 unless TLSProxy::Message->fail();
    my $alert = TLSProxy::Message->alert();
    return 0 if !defined $alert || $alert->server();
    return $alert->description() == TLSProxy::Message::AL_DESC_PROTOCOL_VERSION;
}

sub legacy_version_filter
{
    my $proxy = shift;

    return if !defined $legacy_version;

    foreach my $message (@{$proxy->message_list}) {
        if ($message->mt == TLSProxy::Message::MT_SERVER_HELLO) {
            $message->server_version($legacy_version);
            $message->repack();
        }
    }
}
