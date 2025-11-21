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
use File::Temp qw(tempfile);
use TLSProxy::Proxy;
use TLSProxy::Message;
use Cwd qw(abs_path);

my $test_name = "test_dtls13ack";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/ || $^O =~ /^(MSWin32)$/;

plan skip_all => "$test_name needs the module feature enabled"
    if disabled("module");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "DTLSProxy does not support partial messages"
    if disabled("ec");

plan skip_all => "$test_name needs DTLSv1.3 enabled"
    if disabled("dtls1_3");

$ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("test"));

my $proxy = TLSProxy::Proxy->new_dtls(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

my $testcount = 3;

plan tests => $testcount;
(undef, my $session) = tempfile();

#Test 1: Check that records are acked during an uninterrupted handshake
$proxy->serverflags("-min_protocol DTLSv1.3 -max_protocol DTLSv1.3");
$proxy->clientflags("-min_protocol DTLSv1.3 -max_protocol DTLSv1.3 -groups ?X25519:?P-256");
$proxy->sessionfile($session);
TLSProxy::Message->successondata(1);
skip "TLSProxy could not start", $testcount if !$proxy->start();

my @expected = get_expected_ack_record_numbers();
my @actual = get_actual_acked_record_numbers();
my @missing = record_numbers_missing(\@expected, \@actual);
my $expected_count = @expected;
my $missing_count = @missing;

ok($missing_count == 0 && $expected_count == 3,
    "Check that all record numbers are acked");

# Test 2: Check that records that are missing are not acked during a handshake
$proxy->clear();
my $found_first_client_finish_msg = 0;
$proxy->serverflags("-min_protocol DTLSv1.3 -max_protocol DTLSv1.3");
$proxy->clientflags("-min_protocol DTLSv1.3 -max_protocol DTLSv1.3 -groups ?X25519:?P-256");
$proxy->sessionfile($session);
$proxy->filter(\&drop_first_client_finish_filter);
TLSProxy::Message->successondata(1);
$proxy->start();

@expected = get_expected_ack_record_numbers();
@actual = get_actual_acked_record_numbers();
@missing = record_numbers_missing(\@expected, \@actual);
$expected_count = @expected;
$missing_count = @missing;

ok($missing_count == 1 && $expected_count == 4,
   "Check that all record numbers except one are acked");

# Test 3: Check that client cert and verify messages are also acked
$proxy->clear();
$proxy->filter(undef);
$found_first_client_finish_msg = 0;
$proxy->serverflags("-min_protocol DTLSv1.3 -max_protocol DTLSv1.3 -Verify 1");
$proxy->clientflags("-mtu 2000 -min_protocol DTLSv1.3 -max_protocol DTLSv1.3 -groups ?X25519:?P-256"
                    ." -cert ".srctop_file("apps", "server.pem"));
$proxy->sessionfile($session);
TLSProxy::Message->successondata(1);
$proxy->start();

@expected = get_expected_ack_record_numbers();
@actual = get_actual_acked_record_numbers();
@missing = record_numbers_missing(\@expected, \@actual);
$expected_count = @expected;
$missing_count = @missing;

ok($missing_count == 0 && $expected_count == 5,
    "Check that all record numbers are acked");

unlink $session;

sub get_expected_ack_record_numbers
{
    my $records = $proxy->record_list;
    my @record_numbers = ();

    foreach (@{$records}) {
        my $record = $_;

        if ($record->content_type == TLSProxy::Record::RT_HANDSHAKE
                && $record->{sent}) {
            my $epoch = $record->epoch;
            my $seqnum = $record->seq;
            my $serverissender = $record->serverissender;
            my $recnum = TLSProxy::RecordNumber->new($epoch, $seqnum);

            my @messages = TLSProxy::Message->get_messages($record);

            my $record_should_be_acked = 0;

            foreach (@messages) {
                my $message = $_;
                if (!$serverissender
                    && ($message->mt == TLSProxy::Message::MT_FINISHED
                        || $message->mt == TLSProxy::Message::MT_CERTIFICATE
                        || $message->mt == TLSProxy::Message::MT_COMPRESSED_CERTIFICATE
                        || $message->mt == TLSProxy::Message::MT_CERTIFICATE_VERIFY)
                        || $message->mt == TLSProxy::Message::MT_KEY_UPDATE
                        || $message->mt == TLSProxy::Message::MT_NEW_SESSION_TICKET
                ) {
                    $record_should_be_acked = 1;
                }
            }

            push(@record_numbers, $recnum) if ($record_should_be_acked == 1);
        }
    }

    return @record_numbers;
}

sub get_actual_acked_record_numbers
{
    my @records = @{$proxy->record_list};
    my @record_numbers = ();

    foreach (@records) {
        my $record = $_;

        $record->get_actual_acked_record_numbers(\@record_numbers);
    }
    return @record_numbers;
}

sub record_numbers_missing
{
    my @expected_record_numbers = @{$_[0]};
    my @actual_record_numbers = @{$_[1]};
    my @missing_record_numbers = ();

    foreach (@expected_record_numbers)
    {
        my $found = 0;
        my $expected = $_;

        foreach (@actual_record_numbers) {
            my $actual = $_;
            if ($actual->epoch() == $expected->epoch()
                    && $actual->seqnum() == $expected->seqnum()) {
                $found = 1
            }
        }

        if ($found == 0) {
            push(@missing_record_numbers, $expected);
        }
    }

    return @missing_record_numbers;
}

sub drop_first_client_finish_filter
{
    my $inproxy = shift;

    foreach my $record (@{$inproxy->record_list}) {
        next if ($record->{sent} == 1 || $record->serverissender || $found_first_client_finish_msg == 1);

        my @messages = TLSProxy::Message->get_messages($record);
        foreach my $message (@messages) {
            if ($message->mt == TLSProxy::Message::MT_FINISHED) {
                $record->{sent} = 1;
                $found_first_client_finish_msg = 1;
                last;
            }
        }
    }
}
