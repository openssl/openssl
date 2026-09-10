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
use Cwd qw(abs_path);

my $test_name = "test_ec_point_formats";
setup($test_name);

$ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("test"));

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the module feature enabled"
    if disabled("module");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs TLS 1.2 enabled"
    if disabled("tls1_2");

plan skip_all => "$test_name needs EC enabled"
    if disabled("ec");

# RFC 4492 section 5.1.2 requires the peer's ec_point_formats list to
# contain "uncompressed", but only when an EC cipher suite is actually
# negotiated at TLS 1.2 or below.  The peer's list is irrelevant at TLS
# 1.3 (the extension itself is) and at TLS 1.2 with a non-ECC cipher
# suite.  We mangle the list to contain only "compressed" (0x01) and
# verify the four corner cases: both sides reject in an ECC TLS 1.2
# handshake; both sides tolerate the missing "uncompressed" when TLS 1.3
# or a non-ECC cipher suite is in play.

# Wire format for ec_point_formats: 1-byte length prefix, then the
# ECPointFormat bytes.  "\x01\x01" advertises a list of one format,
# the value 1 = ansiX962_compressed_prime; 0 (uncompressed) is absent.
my $only_compressed = "\x01\x01";

my $fatal_alert = 0;

my $proxy = TLSProxy::Proxy->new(
    \&mangle_ec_point_formats_clienthello,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE}),
);

# Test 1: a non-conforming list in the ClientHello -- the server
# must abort with illegal_parameter.  ECDHE-RSA suffices to
# trigger the check (client supports at least one ECDHE group and
# cipher, so sends the extension), no EC cert required from either
# side.
$proxy->clientflags("-tls1_2");
$proxy->serverflags("-tls1_2");
$proxy->cipherc("ECDHE-RSA-AES128-SHA256");
$proxy->ciphers("ECDHE-RSA-AES128-SHA256");
$proxy->start() or plan skip_all => "Unable to start up proxy for tests";
plan tests => 4;
ok($fatal_alert,
    "Server rejects ClientHello whose ec_point_formats omits uncompressed");

# Test 2: a non-conforming list in the ServerHello -- the client must
# abort with the same error.
$fatal_alert = 0;
$proxy->clear();
$proxy->filter(\&mangle_ec_point_formats_serverhello);
$proxy->clientflags("-tls1_2");
$proxy->serverflags("-tls1_2");
$proxy->cipherc("ECDHE-RSA-AES128-SHA256");
$proxy->ciphers("ECDHE-RSA-AES128-SHA256");
$proxy->start();
ok($fatal_alert,
    "Client rejects ServerHello whose ec_point_formats omits uncompressed");

# Mutating a ClientHello on the wire breaks the handshake transcript
# (the client and server compute different transcript hashes), so a
# tolerance test can't wait for the handshake to complete -- the
# Finished MAC will fail later regardless of whether the construct
# hook rejected.  Instead, the proxy is allowed to run to whatever
# end it finds and we look at $proxy->message_list afterwards: if the
# server sent a ServerHello in response to the mangled ClientHello,
# it accepted the extension; if it rejected, the only server-side
# message in the list will be the fatal alert.
sub server_sent_hello {
    my $proxy = shift;
    foreach my $msg (@{$proxy->message_list}) {
        return 1 if $msg->mt == TLSProxy::Message::MT_SERVER_HELLO;
    }
    return 0;
}

# Test 3: TLS 1.3 ignores the ec_point_formats extension entirely.  The
# server doesn't emit one in its TLS 1.3 ServerHello, and the
# construct-hook 5.1.2 check requires an ECC TLS <= 1.2 ciphersuite
# to fire.  A mangled ClientHello list must therefore leave the server
# willing to send its ServerHello.
SKIP: {
    skip "TLS 1.3 disabled", 1 if disabled("tls1_3");

    $fatal_alert = 0;
    $proxy->clear();
    $proxy->filter(\&mangle_ec_point_formats_clienthello);
    $proxy->clientflags("-tls1_3");
    $proxy->serverflags("-tls1_3");
    $proxy->start();
    ok(server_sent_hello($proxy),
        "TLS 1.3 server tolerates ec_point_formats missing uncompressed");
}

# Test 4: At TLS 1.2 with a non-ECC cipher suite, the construct hook
# returns NOT_SENT without inspecting the peer's list.  Offer ECDHE-RSA
# alongside DHE-RSA on the client -- the ECDHE entry is enough for the
# client to advertise ec_point_formats -- pin the server to DHE-RSA,
# and confirm a mangled list is tolerated.
SKIP: {
    skip "DH disabled", 1 if disabled("dh");

    $fatal_alert = 0;
    $proxy->clear();
    $proxy->filter(\&mangle_ec_point_formats_clienthello);
    $proxy->clientflags("-tls1_2");
    $proxy->serverflags("-tls1_2");
    $proxy->cipherc("ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-GCM-SHA256");
    $proxy->ciphers("DHE-RSA-AES128-GCM-SHA256");
    $proxy->start();
    ok(server_sent_hello($proxy),
        "TLS 1.2 non-ECC server tolerates ec_point_formats missing uncompressed");
}

sub mangle_ec_point_formats_clienthello
{
    my $proxy = shift;

    if ($proxy->flight == 0) {
        foreach my $message (@{$proxy->message_list}) {
            if ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO) {
                $message->set_extension(
                    TLSProxy::Message::EXT_EC_POINT_FORMATS,
                    $only_compressed);
                $message->repack();
            }
        }
        return;
    }

    my $last_record = @{$proxy->{record_list}}[-1];
    $fatal_alert = 1
        if defined $last_record && $last_record->is_fatal_alert(1);
}

sub mangle_ec_point_formats_serverhello
{
    my $proxy = shift;

    if ($proxy->flight == 0) {
        return;
    } elsif ($proxy->flight == 1) {
        foreach my $message (@{$proxy->message_list}) {
            if ($message->mt == TLSProxy::Message::MT_SERVER_HELLO) {
                $message->set_extension(
                    TLSProxy::Message::EXT_EC_POINT_FORMATS,
                    $only_compressed);
                $message->repack();
            }
        }
        return;
    }

    my $last_record = @{$proxy->{record_list}}[-1];
    $fatal_alert = 1
        if defined $last_record && $last_record->is_fatal_alert(0);
}
