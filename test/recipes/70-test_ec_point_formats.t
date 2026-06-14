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

# RFC 4492 section 5.1.2 requires the peer's ec_point_formats list to contain
# "uncompressed".  We mangle the list to contain only "compressed" (0x01) and
# verify the receiver aborts the handshake on both sides.

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

# Test 1: a non-conforming list in the ClientHello -- the server must
# abort with illegal_parameter.  ECDHE-RSA suffices to trigger the
# check (alg_k = SSL_kECDHE), no EC cert required.
$proxy->clientflags("-tls1_2");
$proxy->serverflags("-tls1_2");
$proxy->cipherc("ECDHE-RSA-AES128-SHA256");
$proxy->ciphers("ECDHE-RSA-AES128-SHA256");
$proxy->start() or plan skip_all => "Unable to start up proxy for tests";
plan tests => 2;
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
    $fatal_alert = 1 if $last_record->is_fatal_alert(1);
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
    $fatal_alert = 1 if $last_record->is_fatal_alert(0);
}
