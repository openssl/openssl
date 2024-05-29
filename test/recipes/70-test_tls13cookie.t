#! /usr/bin/env perl
# Copyright 2017-2025 The OpenSSL Project Authors. All Rights Reserved.
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

my $test_name = "test_tls13cookie";
setup($test_name);

$ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("test"));

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the module feature enabled"
    if disabled("module");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs EC and DH enabled"
    if disabled("ec") && disabled("dh");

my $testcount = 2;

plan tests => 2 * $testcount;

SKIP: {
    skip "TLS 1.3 is disabled", $testcount if disabled("tls1_3");
    # Run tests with TLS
    run_tests(0);
}

SKIP: {
    skip "DTLS 1.3 is disabled", $testcount if disabled("dtls1_3");
    skip "DTLSProxy does not work on Windows", $testcount if $^O =~ /^(MSWin32)$/;
    run_tests(1);
}

use constant {
    COOKIE_ONLY => 0,
    COOKIE_AND_KEY_SHARE => 1
};

my $cookieseen = 0;
my $testtype;

sub run_tests
{
    my $run_test_as_dtls = shift;
    my $proxy_start_success = 0;
    my $proxy;
    if ($run_test_as_dtls == 1) {
        $proxy = TLSProxy::Proxy->new_dtls(
            undef,
            cmdstr(app([ "openssl" ]), display => 1),
            srctop_file("apps", "server.pem"),
            (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
        );
    }
    else {
        $proxy = TLSProxy::Proxy->new(
            undef,
            cmdstr(app([ "openssl" ]), display => 1),
            srctop_file("apps", "server.pem"),
            (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
        );
    }

    #Test 1: Inserting a cookie into an HRR should see it echoed in the ClientHello
    #        (when a key share is required)
    $testtype = COOKIE_AND_KEY_SHARE;
    $proxy->filter(\&cookie_filter);
    if (disabled("ecx")) {
        $proxy->clientflags("-curves ffdhe3072:ffdhe2048");
        $proxy->serverflags("-curves ffdhe2048");
    } else {
        $proxy->clientflags("-curves P-256:X25519");
        $proxy->serverflags("-curves X25519");
    }
    $proxy_start_success = $proxy->start();
    skip "TLSProxy did not start correctly", $testcount if $proxy_start_success == 0;
    ok(TLSProxy::Message->success() && $cookieseen == 1, "Cookie seen");

    #Test 2: Inserting a cookie into an HRR should see it echoed in the ClientHello
    #        (without a key share required)
    SKIP: {
        skip "ECX disabled", 1, if (disabled("ecx"));
        $testtype = COOKIE_ONLY;
        $proxy->clear();
        $proxy->serverflags("-curves X25519");
        $proxy->clientflags("-curves X25519:secp256r1");
        $proxy->start();
        ok(TLSProxy::Message->success() && $cookieseen == 1, "Cookie seen");
    }
}

sub cookie_filter
{
    my $proxy = shift;

    # We're only interested in the HRR and both ClientHellos
    return if ($proxy->flight > 2);

    my $ext = pack "C8",
        0x00, 0x06, #Cookie Length
        0x00, 0x01, #Dummy cookie data (6 bytes)
        0x02, 0x03,
        0x04, 0x05;

    foreach my $message (@{$proxy->message_list}) {
        if ($message->mt == TLSProxy::Message::MT_SERVER_HELLO
                && ${$message->records}[0]->flight == 1) {
            $message->delete_extension(TLSProxy::Message::EXT_KEY_SHARE)
                if ($testtype == COOKIE_ONLY);
            $message->set_extension(TLSProxy::Message::EXT_COOKIE, $ext);
            $message->repack();
        } elsif ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO) {
            if (${$message->records}[0]->flight == 0) {
                if ($testtype == COOKIE_ONLY) {
                    my $ext = pack "C7",
                        0x00, 0x05, #List Length
                        0x00, 0x17, #P-256
                        0x00, 0x01, #key_exchange data length
                        0xff;       #Dummy key_share data
                    # Trick the server into thinking we got an unacceptable
                    # key_share
                    $message->set_extension(
                        TLSProxy::Message::EXT_KEY_SHARE, $ext);
                    $message->repack();
                }
            } else {
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
}
