#! /usr/bin/env perl
# Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;

my $test_name = "test_tls13cookie";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS|MSWin32)$/;

plan skip_all => "$test_name needs the dynamic engine feature enabled"
    if disabled("engine") || disabled("dynamic-engine");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs TLS1.3 enabled"
    if disabled("tls1_3");

$ENV{OPENSSL_ia32cap} = '~0x200000200000000';

my $proxy = TLSProxy::Proxy->new(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

my $cookieseen = 0;

#Test 1: Inserting a cookie into an HRR should see it echoed in the ClientHello
$proxy->filter(\&cookie_filter);
$proxy->serverflags("-curves P-256");
$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
plan tests => 1;
ok(TLSProxy::Message->success() && $cookieseen == 1, "Cookie seen");

sub cookie_filter
{
    my $proxy = shift;

    # We're only interested in the HRR and subsequent ClientHello
    if ($proxy->flight != 1 && $proxy->flight != 2) {
        return;
    }

    my $ext = pack "C8",
        0x00, 0x06, #Cookie Length
        0x00, 0x01, #Dummy cookie data (6 bytes)
        0x02, 0x03,
        0x04, 0x05;

    foreach my $message (@{$proxy->message_list}) {
        if ($message->mt == TLSProxy::Message::MT_HELLO_RETRY_REQUEST) {

            $message->set_extension(TLSProxy::Message::EXT_COOKIE, $ext);
            $message->repack();
        } elsif ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO
                    && ${$message->records}[0]->flight == 2) {
            #cmp can behave differently dependent on locale
            no locale;
            my $cookie =
                $message->extension_data->{TLSProxy::Message::EXT_COOKIE};

            return if !defined($cookie);

            return if ($cookie cmp $ext) != 0;

            $cookieseen = 1;
        }
    }
}
