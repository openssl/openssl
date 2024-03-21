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

plan skip_all => "$test_name needs DTLSv1.3 enabled"
    if disabled("dtls1_3");

my $proxy = TLSProxy::Proxy->new_dtls(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

plan tests => 3;

my $epoch_check_failed;
my $latest_epoch;

#Test 1: Check that epoch is incremented as expected during a handshake
$epoch_check_failed = 0;
$latest_epoch = 0;
$proxy->serverflags("-min_protocol DTLSv1.3 -max_protocol DTLSv1.3");
$proxy->clientflags("-min_protocol DTLSv1.3 -max_protocol DTLSv1.3");
$proxy->filter(\&current_record_epoch_filter);
TLSProxy::Message->successondata(1);
ok($proxy->start(), "Proxy run succeeded");
ok(!$epoch_check_failed, "Epoch changes correctly during handshake");
ok($latest_epoch == 3, "Epoch ends being 3 after successful handshake");

sub current_record_epoch_filter
{
    my $records = $proxy->record_list;
    my $latest_record = @{$records}[-1];
    my $epoch = $latest_record->epoch;
    my @badmessagetypes = undef;

    $latest_epoch = $epoch;
    if ($epoch == 0) {
        @badmessagetypes = (
            TLSProxy::Message::MT_NEW_SESSION_TICKET,
            TLSProxy::Message::MT_ENCRYPTED_EXTENSIONS,
            TLSProxy::Message::MT_CERTIFICATE,
            TLSProxy::Message::MT_SERVER_KEY_EXCHANGE,
            TLSProxy::Message::MT_CERTIFICATE_REQUEST,
            TLSProxy::Message::MT_SERVER_HELLO_DONE,
            TLSProxy::Message::MT_CERTIFICATE_VERIFY,
            TLSProxy::Message::MT_CLIENT_KEY_EXCHANGE,
            TLSProxy::Message::MT_FINISHED,
            TLSProxy::Message::MT_CERTIFICATE_STATUS,
            TLSProxy::Message::MT_COMPRESSED_CERTIFICATE,
            TLSProxy::Message::MT_NEXT_PROTO
        );
    } elsif ($epoch == 1) {
        @badmessagetypes = (
            TLSProxy::Message::MT_NEW_SESSION_TICKET,
            TLSProxy::Message::MT_ENCRYPTED_EXTENSIONS,
            TLSProxy::Message::MT_CERTIFICATE,
            TLSProxy::Message::MT_SERVER_KEY_EXCHANGE,
            TLSProxy::Message::MT_CERTIFICATE_REQUEST,
            TLSProxy::Message::MT_SERVER_HELLO_DONE,
            TLSProxy::Message::MT_CERTIFICATE_VERIFY,
            TLSProxy::Message::MT_CLIENT_KEY_EXCHANGE,
            TLSProxy::Message::MT_FINISHED,
            TLSProxy::Message::MT_CERTIFICATE_STATUS,
            TLSProxy::Message::MT_COMPRESSED_CERTIFICATE,
            TLSProxy::Message::MT_NEXT_PROTO
        );

    } elsif ($epoch == 2) {
        @badmessagetypes = (
            TLSProxy::Message::MT_NEW_SESSION_TICKET,
            TLSProxy::Message::MT_CERTIFICATE_STATUS,
            TLSProxy::Message::MT_COMPRESSED_CERTIFICATE,
            TLSProxy::Message::MT_NEXT_PROTO
        );
    }

    # Check that message types are acceptable
    foreach (@{$proxy->message_list})
    {
        my $mt = $_->mt;

        if (grep(/^$mt$/, @badmessagetypes)) {
            print "Did not expect $mt in epoch $latest_epoch\n";
            $epoch_check_failed = 1;
        }
    }
}
