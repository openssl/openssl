#! /usr/bin/env perl
# Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;

my $test_name = "test_tls13downgrade";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the dynamic engine feature enabled"
    if disabled("engine") || disabled("dynamic-engine");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs TLS1.3 and TLS1.2 enabled"
    if disabled("tls1_3") || disabled("tls1_2")
        || (disabled("ec") && disabled("dh"));

my $proxy = TLSProxy::Proxy->new(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

use constant {
    DOWNGRADE_TO_TLS_1_2 => 0,
    DOWNGRADE_TO_TLS_1_1 => 1,
    FALLBACK_FROM_TLS_1_3 => 2,
    DOWNGRADE_TO_TLS_1_2_WITH_TLS_1_1_SIGNAL => 3,
    DOWNGRADE_TO_TLS_1_1_WITH_TLS_1_2_SIGNAL => 4,
};

#Test 1: Downgrade from TLSv1.3 to TLSv1.2
$proxy->filter(\&downgrade_filter);
my $testtype = DOWNGRADE_TO_TLS_1_2;
$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
plan tests => 8;
ok(is_illegal_parameter_client_alert(), "Downgrade TLSv1.3 to TLSv1.2");

#Test 2: Downgrade from TLSv1.3 to TLSv1.2 (server sends TLSv1.1 signal)
$proxy->clear();
$testtype = DOWNGRADE_TO_TLS_1_2_WITH_TLS_1_1_SIGNAL;
$proxy->start();
ok(is_illegal_parameter_client_alert(),
   "Downgrade from TLSv1.3 to TLSv1.2 (server sends TLSv1.1 signal)");

#Test 3: Client falls back from TLSv1.3 (server does not support the fallback
#        SCSV)
$proxy->clear();
$testtype = FALLBACK_FROM_TLS_1_3;
$proxy->clientflags("-fallback_scsv -no_tls1_3");
$proxy->start();
ok(is_illegal_parameter_client_alert(), "Fallback from TLSv1.3");

SKIP: {
    skip "TLSv1.1 disabled", 5 if disabled("tls1_1");

    my $client_flags = "-min_protocol TLSv1.1 -cipher DEFAULT:\@SECLEVEL=0";
    my $server_flags = "-min_protocol TLSv1.1";
    my $ciphers = "AES128-SHA:\@SECLEVEL=0";

    #Test 4: Downgrade from TLSv1.3 to TLSv1.1
    $proxy->clear();
    $testtype = DOWNGRADE_TO_TLS_1_1;
    $proxy->clientflags($client_flags);
    $proxy->serverflags($server_flags);
    $proxy->ciphers($ciphers);
    $proxy->start();
    ok(is_illegal_parameter_client_alert(), "Downgrade TLSv1.3 to TLSv1.1");

    #Test 5: Downgrade from TLSv1.3 to TLSv1.1 (server sends TLSv1.2 signal)
    $proxy->clear();
    $testtype = DOWNGRADE_TO_TLS_1_1_WITH_TLS_1_2_SIGNAL;
    $proxy->clientflags($client_flags);
    $proxy->serverflags($server_flags);
    $proxy->ciphers($ciphers);
    $proxy->start();
    ok(is_illegal_parameter_client_alert(),
       "Downgrade TLSv1.3 to TLSv1.1 (server sends TLSv1.2 signal)");

    #Test 6: Downgrade from TLSv1.2 to TLSv1.1
    $proxy->clear();
    $testtype = DOWNGRADE_TO_TLS_1_1;
    $proxy->clientflags($client_flags." -max_protocol TLSv1.2");
    $proxy->serverflags($server_flags." -max_protocol TLSv1.2");
    $proxy->ciphers($ciphers);
    $proxy->start();
    ok(is_illegal_parameter_client_alert(), "Downgrade TLSv1.2 to TLSv1.1");

    #Test 7: A client side protocol "hole" should not be detected as a downgrade
    $proxy->clear();
    $proxy->filter(undef);
    $proxy->clientflags($client_flags." -no_tls1_2");
    $proxy->serverflags($server_flags);
    $proxy->ciphers($ciphers);
    $proxy->start();
    ok(TLSProxy::Message->success(), "TLSv1.2 client-side protocol hole");

    #Test 8: A server side protocol "hole" should not be detected as a downgrade
    $proxy->clear();
    $proxy->filter(undef);
    $proxy->clientflags($client_flags);
    $proxy->serverflags($server_flags." -no_tls1_2");
    $proxy->ciphers($ciphers);
    $proxy->start();
    ok(TLSProxy::Message->success(), "TLSv1.2 server-side protocol hole");
}

# Validate that the exchange fails with an illegal parameter alert from
#  the client
sub is_illegal_parameter_client_alert
{
    return 0 unless TLSProxy::Message->fail();
    my $alert = TLSProxy::Message->alert();
    return 1 if !$alert->server()
                && $alert->description()
                   == TLSProxy::Message::AL_DESC_ILLEGAL_PARAMETER;
    return 0;
}

sub downgrade_filter
{
    my $proxy = shift;

    # We're only interested in the initial ClientHello and ServerHello
    if ($proxy->flight > 1) {
        return;
    }

    my $message = ${$proxy->message_list}[$proxy->flight];

    # ServerHello
    if ($proxy->flight == 1 && defined($message)) {
        # Update the last byte of the downgrade signal
        if ($testtype == DOWNGRADE_TO_TLS_1_2_WITH_TLS_1_1_SIGNAL) {
            $message->random(substr($message->random, 0, 31) . "\0");
            $message->repack();
        } elsif ($testtype == DOWNGRADE_TO_TLS_1_1_WITH_TLS_1_2_SIGNAL) {
            $message->random(substr($message->random, 0, 31) . "\1");
            $message->repack();
        }

        return;
    }

    # ClientHello
    if ($proxy->flight == 0) {
        my $ext;
        if ($testtype == FALLBACK_FROM_TLS_1_3) {
            #The default ciphersuite we use for TLSv1.2 without any SCSV
            my @ciphersuites = (TLSProxy::Message::CIPHER_RSA_WITH_AES_128_CBC_SHA);
            $message->ciphersuite_len(2 * scalar @ciphersuites);
            $message->ciphersuites(\@ciphersuites);
        }
        else {
            if ($testtype == DOWNGRADE_TO_TLS_1_2
                || $testtype == DOWNGRADE_TO_TLS_1_2_WITH_TLS_1_1_SIGNAL) {
                $ext = pack "C3",
                    0x02,       # Length
                    0x03, 0x03; #TLSv1.2
            }
            else {
                $ext = pack "C3",
                    0x02,       # Length
                    0x03, 0x02; #TLSv1.1
            }

            $message->set_extension(TLSProxy::Message::EXT_SUPPORTED_VERSIONS,
                                    $ext);
        }

        $message->repack();
    }
}

