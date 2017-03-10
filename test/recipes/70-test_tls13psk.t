#! /usr/bin/env perl
# Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file srctop_dir bldtop_dir/;
use OpenSSL::Test::Utils;
use File::Temp qw(tempfile);
use TLSProxy::Proxy;

my $test_name = "test_tls13psk";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS|MSWin32)$/;

plan skip_all => "$test_name needs the dynamic engine feature enabled"
    if disabled("engine") || disabled("dynamic-engine");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs TLSv1.3 enabled"
    if disabled("tls1_3");

$ENV{OPENSSL_ia32cap} = '~0x200000200000000';
$ENV{CTLOG_FILE} = srctop_file("test", "ct", "log_list.conf");

my $proxy = TLSProxy::Proxy->new(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

#Most PSK tests are done in test_ssl_new. This just checks sending a PSK
#extension when it isn't in the last place in a ClientHello

#Test 1: First get a session
(undef, my $session) = tempfile();
$proxy->clientflags("-sess_out ".$session);
$proxy->sessionfile($session);
$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
plan tests => 2;
ok(TLSProxy::Message->success(), "Initial connection");

#Test 2: Attempt a resume with PSK not in last place. Should fail
$proxy->clear();
$proxy->clientflags("-sess_in ".$session);
$proxy->filter(\&modify_psk_filter);
$proxy->start();
ok(TLSProxy::Message->fail(), "PSK not last");

unlink $session;

sub modify_psk_filter
{
    my $proxy = shift;

    # We're only interested in the initial ClientHello
    return if ($proxy->flight != 0);

    foreach my $message (@{$proxy->message_list}) {
        if ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO) {
            $message->set_extension(TLSProxy::Message::EXT_FORCE_LAST, "");
            $message->repack();
        }
    }
}
