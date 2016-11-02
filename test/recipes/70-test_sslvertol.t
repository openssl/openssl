#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;

my $test_name = "test_sslextension";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS|MSWin32)$/;

plan skip_all => "$test_name needs the dynamic engine feature enabled"
    if disabled("engine") || disabled("dynamic-engine");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs TLS enabled"
    if alldisabled(available_protocols("tls"));

$ENV{OPENSSL_ia32cap} = '~0x200000200000000';
my $proxy = TLSProxy::Proxy->new(
    \&vers_tolerance_filter,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

#This file does tests without the supported_versions extension.
#See 70-test_sslversions.t for tests with supported versions.
#Test 1: Asking for TLS1.4 should pass and negotiate TLS1.2
my $client_version = TLSProxy::Record::VERS_TLS_1_4;
$proxy->clientflags("-no_tls1_3");
$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
plan tests => 3;
my $record = pop @{$proxy->record_list};
ok(TLSProxy::Message->success()
   && $record->version() == TLSProxy::Record::VERS_TLS_1_2,
   "Version tolerance test, TLS 1.4");

#Test 2: Asking for TLS1.3 should succeed and negotiate TLS1.2
$proxy->clear();
$proxy->clientflags("-no_tls1_3");
$proxy->start();
$record = pop @{$proxy->record_list};
ok(TLSProxy::Message->success()
   && $record->version() == TLSProxy::Record::VERS_TLS_1_2,
   "Version tolerance test, TLS 1.3");

#Test 3: Testing something below SSLv3 should fail
$client_version = TLSProxy::Record::VERS_SSL_3_0 - 1;
$proxy->clear();
$proxy->clientflags("-no_tls1_3");
$proxy->start();
ok(TLSProxy::Message->fail(), "Version tolerance test, SSL < 3.0");

sub vers_tolerance_filter
{
    my $proxy = shift;

    # We're only interested in the initial ClientHello
    if ($proxy->flight != 0) {
        return;
    }

    foreach my $message (@{$proxy->message_list}) {
        if ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO) {
            #Set the client version
            #Anything above the max supported version (TLS1.2) should succeed
            #Anything below SSLv3 should fail
            $message->client_version($client_version);
            $message->repack();
        }
    }
}
