#! /usr/bin/env perl
# Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;

my $test_name = "test_sslrecords";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS|MSWin32)$/;

plan skip_all => "$test_name needs the dynamic engine feature enabled"
    if disabled("engine") || disabled("dynamic-engine");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs TLSv1.2 enabled"
    if disabled("tls1_2");

$ENV{OPENSSL_ia32cap} = '~0x200000200000000';
my $proxy = TLSProxy::Proxy->new(
    \&add_empty_recs_filter,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

#Test 1: Injecting out of context empty records should fail
my $content_type = TLSProxy::Record::RT_APPLICATION_DATA;
my $inject_recs_num = 1;
$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
plan tests => 4;
ok(TLSProxy::Message->fail(), "Out of context empty records test");

#Test 2: Injecting in context empty records should succeed
$proxy->clear();
$content_type = TLSProxy::Record::RT_HANDSHAKE;
$proxy->start();
ok(TLSProxy::Message->success(), "In context empty records test");

#Test 3: Injecting too many in context empty records should fail
$proxy->clear();
#We allow 32 consecutive in context empty records
$inject_recs_num = 33;
$proxy->start();
ok(TLSProxy::Message->fail(), "Too many in context empty records test");

#Test 4: Injecting a fragmented fatal alert should fail. We actually expect no
#        alerts to be sent from either side because *we* injected the fatal
#        alert, i.e. this will look like a disorderly close
$proxy->clear();
$proxy->filter(\&add_frag_alert_filter);
$proxy->start();
ok(!TLSProxy::Message->end(), "Fragmented alert records test");

sub add_empty_recs_filter
{
    my $proxy = shift;

    # We're only interested in the initial ClientHello
    if ($proxy->flight != 0) {
        return;
    }

    for (my $i = 0; $i < $inject_recs_num; $i++) {
        my $record = TLSProxy::Record->new(
            0,
            $content_type,
            TLSProxy::Record::VERS_TLS_1_2,
            0,
            0,
            0,
            "",
            ""
        );

        push @{$proxy->record_list}, $record;
    }
}

sub add_frag_alert_filter
{
    my $proxy = shift;
    my $byte;

    # We're only interested in the initial ClientHello
    if ($proxy->flight != 0) {
        return;
    }

    # Add a zero length fragment first
    #my $record = TLSProxy::Record->new(
    #    0,
    #    TLSProxy::Record::RT_ALERT,
    #    TLSProxy::Record::VERS_TLS_1_2,
    #    0,
    #    0,
    #    0,
    #    "",
    #    ""
    #);
    #push @{$proxy->record_list}, $record;

    # Now add the alert level (Fatal) as a seperate record
    $byte = pack('C', TLSProxy::Message::AL_LEVEL_FATAL);
    my $record = TLSProxy::Record->new(
        0,
        TLSProxy::Record::RT_ALERT,
        TLSProxy::Record::VERS_TLS_1_2,
        1,
        1,
        1,
        $byte,
        $byte
    );
    push @{$proxy->record_list}, $record;

    # And finally the description (Unexpected message) in a third record
    $byte = pack('C', TLSProxy::Message::AL_DESC_UNEXPECTED_MESSAGE);
    $record = TLSProxy::Record->new(
        0,
        TLSProxy::Record::RT_ALERT,
        TLSProxy::Record::VERS_TLS_1_2,
        1,
        1,
        1,
        $byte,
        $byte
    );
    push @{$proxy->record_list}, $record;
}
