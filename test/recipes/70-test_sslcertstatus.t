#! /usr/bin/env perl
# Copyright 2015-2026 The OpenSSL Project Authors. All Rights Reserved.
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

my $test_name = "test_sslcertstatus";
setup($test_name);

$ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("test"));

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the module feature enabled"
    if disabled("module");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs the ocsp feature enabled"
    if disabled("ocsp");

plan skip_all => "$test_name needs TLS enabled"
    if alldisabled(available_protocols("tls"))
       || (!disabled("tls1_3") && disabled("tls1_2"));

my $proxy = TLSProxy::Proxy->new(
    \&certstatus_filter,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE}),
    have_IPv6()
);

#Test 1: Sending a status_request extension in both ClientHello and
#ServerHello but then omitting the CertificateStatus message is valid
$proxy->clientflags("-status -no_tls1_3");
$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
plan tests => 2;
ok(TLSProxy::Message->success, "Missing CertificateStatus message");

#Test 2: In TLS 1.3 a status_request extension in the server CertificateEntry
#whose CertificateStatus body has only the status_type byte and is missing the
#mandatory OCSPResponse must abort the handshake with a decode_error
$proxy->clear();
$proxy->clientflags("-status");
$proxy->start();
ok(is_alert_message(TLSProxy::Message::AL_DESC_DECODE_ERROR),
   "Incomplete CertificateStatus body");

sub certstatus_filter
{
    my $proxy = shift;

    foreach my $message (@{$proxy->message_list}) {
        if (TLSProxy::Proxy->is_tls13()) {
            #Test 2: Send a status_request extension in the server first
            #CertificateEntry whose body is only the status_type byte
            next unless $message->server()
                && $message->mt == TLSProxy::Message::MT_CERTIFICATE;
            $message->set_extension(TLSProxy::Message::EXT_STATUS_REQUEST,
                                    "\x01");
        } elsif ($message->mt == TLSProxy::Message::MT_SERVER_HELLO) {
            #Test 1: Add the status_request to the ServerHello even though we
            #are not going to send a CertificateStatus message
            $message->set_extension(TLSProxy::Message::EXT_STATUS_REQUEST,
                                    "");
        } else {
            next;
        }
        $message->repack();
    }
}

# Test if the last message was a failure and matches the expected alert type.
sub is_alert_message
{
    my $alert_type = shift;
    return 0 unless TLSProxy::Message->fail();
    return 1 if TLSProxy::Message->alert->description() == $alert_type;
    return 0;
}
