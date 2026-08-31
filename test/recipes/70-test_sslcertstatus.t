#! /usr/bin/env perl
# Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
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

#Test 2: Sending a status_request extension with more than 16 OCSP responder IDs
#should be fine. We should just ignore the ones beyond the first 16.
$proxy->clear();
$proxy->serverflags("-status");
$proxy->filter(\&modify_cert_status_filter);
$proxy->start();
ok(TLSProxy::Message->success(), "Large number of OCSP responder IDs");

sub certstatus_filter
{
    my $proxy = shift;

    # We're only interested in the initial ServerHello
    if ($proxy->flight != 1) {
        return;
    }

    foreach my $message (@{$proxy->message_list}) {
        if ($message->mt == TLSProxy::Message::MT_SERVER_HELLO) {
            #Add the status_request to the ServerHello even though we are not
            #going to send a CertificateStatus message
            $message->set_extension(TLSProxy::Message::EXT_STATUS_REQUEST,
                                    "");

            $message->repack();
        }
    }
}

sub modify_cert_status_filter
{
    my $proxy = shift;

    # We're only interested in the initial ClientHello
    if ($proxy->flight != 0) {
        return;
    }

    foreach my $message (@{$proxy->message_list}) {
        if ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO) {
            my $ext;

            # We include 17 OCSP responder IDs (we only accept the first 16).
            # We should just ignore them and still succeed
            $ext = pack "C107",
                0x01, # Status type OCSP
                0x00, 0x66, #List Length (102 bytes)
                (0x00, 0x04, 0xA2, 0x02, 0x04, 0x00)x17, #17 dummy OCSP responder IDs
                0x00, 0x00; # No extensions

            $message->set_extension(TLSProxy::Message::EXT_STATUS_REQUEST, $ext);

            $message->repack();
        }
    }
}
