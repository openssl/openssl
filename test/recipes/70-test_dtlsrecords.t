#! /usr/bin/env perl
# Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use feature 'state';

use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;
use TLSProxy::Message;

my $test_name = "test_dtlsrecords";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the dynamic engine feature enabled"
    if disabled("engine") || disabled("dynamic-engine");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs DTLSv1.2 enabled"
    if disabled("dtls1_2");

my $proxy = TLSProxy::Proxy->new_dtls(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

plan tests => 4;

my $fatal_alert = 0;        # set by filters at expected fatal alerts
my $inject_recs_num = 0;    # used by add_empty_recs_filter
my $proxy_start_success = 0;

#Test 1: Injecting out of context empty records should succeed
my $content_type = TLSProxy::Record::RT_APPLICATION_DATA;
$inject_recs_num = 1;
$proxy->serverflags("-min_protocol DTLSv1.2 -max_protocol DTLSv1.2");
$proxy->clientflags("-max_protocol DTLSv1.2");
$proxy->filter(\&add_empty_recs_filter);
$proxy_start_success = $proxy->start();
ok($proxy_start_success && TLSProxy::Message->success(), "Out of context empty records test");

#Test 2: Injecting in context empty records should succeed
$proxy->clear();
$content_type = TLSProxy::Record::RT_HANDSHAKE;
$inject_recs_num = 1;
$proxy->serverflags("-min_protocol DTLSv1.2 -max_protocol DTLSv1.2");
$proxy->clientflags("-max_protocol DTLSv1.2");
$proxy->filter(\&add_empty_recs_filter);
$proxy_start_success = $proxy->start();
ok($proxy_start_success && TLSProxy::Message->success(), "In context empty records test");

#Unrecognised record type tests

#Test 3: Sending an unrecognised record type in DTLSv1.2 should fail
$fatal_alert = 0;
$proxy->clear();
$proxy->serverflags("-min_protocol DTLSv1.2 -max_protocol DTLSv1.2");
$proxy->clientflags("-max_protocol DTLSv1.2");
$proxy->filter(\&add_unknown_record_type);
ok($proxy->start() == 0, "Unrecognised record type in DTLS1.2");

SKIP: {
    skip "DTLSv1 disabled", 1 if disabled("dtls1");

    #Test 4: Sending an unrecognised record type in DTLSv1 should fail
    $fatal_alert = 0;
    $proxy->clear();
    $proxy->clientflags("-min_protocol DTLSv1 -max_protocol DTLSv1 -cipher DEFAULT:\@SECLEVEL=0");
    $proxy->ciphers("AES128-SHA:\@SECLEVEL=0");
    $proxy->filter(\&add_unknown_record_type);
    ok($proxy->start() == 0, "Unrecognised record type in DTLSv1");
}

sub add_empty_recs_filter
{
    my $proxy = shift;
    my $records = $proxy->record_list;

    # We're only interested in the initial ClientHello
    if ($proxy->flight != 0) {
        $fatal_alert = 1 if @{$records}[-1]->is_fatal_alert(1) == TLSProxy::Message::AL_DESC_UNEXPECTED_MESSAGE;
        return;
    }

    for (my $i = 0; $i < $inject_recs_num; $i++) {
        my $record = TLSProxy::Record->new_dtls(
            0,
            $content_type,
            TLSProxy::Record::VERS_TLS_1_2,
            0,
            0,
            0,
            0,
            0,
            0,
            "",
            ""
        );
        push @{$records}, $record;
    }
}

sub add_unknown_record_type
{
    my $proxy = shift;
    my $records = $proxy->record_list;
    state $added_record;

    # We'll change a record after the initial version neg has taken place
    if ($proxy->flight == 0) {
        $added_record = 0;
        return;
    } elsif ($proxy->flight != 1 || $added_record) {
        $fatal_alert = 1 if @{$records}[-1]->is_fatal_alert(0) == TLSProxy::Message::AL_DESC_UNEXPECTED_MESSAGE;
        return;
    }

    my $record = TLSProxy::Record->new_dtls(
        1,
        TLSProxy::Record::RT_UNKNOWN,
        @{$records}[-1]->version(),
        @{$records}[-1]->epoch(),
        @{$records}[-1]->seq() +1,
        1,
        0,
        1,
        1,
        "X",
        "X"
    );

    #Find ServerHello record and insert after that
    my $i;
    for ($i = 0; ${$proxy->record_list}[$i]->flight() < 1; $i++) {
        next;
    }
    $i++;

    splice @{$proxy->record_list}, $i, 0, $record;
    $added_record = 1;
}
