#! /usr/bin/env perl
# Copyright 2018-2021 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;

my $test_name = "test_tls13alerts";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the dynamic engine feature enabled"
    if disabled("engine") || disabled("dynamic-engine");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs elliptic curves or diffie-hellman enabled"
    if disabled("ec") && disabled("dh");

my $testcount = 1;

plan tests => 2 * $testcount;

SKIP: {
    skip "TLS 1.3 is disabled", $testcount if disabled("tls1_3");
    # Run tests with TLS
    run_tests(0);
}

SKIP: {
    skip "DTLS 1.3 is disabled", $testcount if disabled("dtls1_3");
    skip "DTLSProxy does not support partial messages that are sent when EC is disabled",
        $testcount if disabled("ec");
    skip "DTLSProxy does not work on Windows", $testcount if $^O =~ /^(MSWin32)$/;
    run_tests(1);
}

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
            cmdstr(app(["openssl"]), display => 1),
            srctop_file("apps", "server.pem"),
            (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
        );
    }

    SKIP: {
        skip "TODO(DTLSv1.3): Test fails because client sends alert with 0 epoch but"
            . " the server increments the epoch after sending ServerHello and thus"
            . " does not accept the alert message.",
            $testcount if $run_test_as_dtls == 1;
        #Test 1: We test that a server can handle an unencrypted alert when normally the
        #        next message is encrypted
        $proxy->clear();
        $proxy->filter(\&alert_filter);
        $proxy_start_success = $proxy->start();
        skip "TLSProxy did not start correctly", $testcount if $proxy_start_success == 0;

        my $alert = TLSProxy::Message->alert();
        ok(TLSProxy::Message->fail() && !$alert->server() && !$alert->encrypted(), "Client sends an unencrypted alert");
    }
}

sub alert_filter
{
    my $proxy = shift;

    if ($proxy->flight != 1) {
        return;
    }

    ${$proxy->message_list}[1]->session_id_len(1);
    ${$proxy->message_list}[1]->repack();
}
