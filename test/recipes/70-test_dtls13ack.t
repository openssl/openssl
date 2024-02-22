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

my $test_name = "test_dtls13ack";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the dynamic engine feature enabled"
    if disabled("engine") || disabled("dynamic-engine");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "DTLSProxy does not support partial messages"
    if disabled("ec");

plan skip_all => "$test_name needs DTLSv1.3 enabled"
    if disabled("dtls1_3");

my $proxy = TLSProxy::Proxy->new_dtls(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

plan tests => 8;

#Test 1: Check that records are acked during an uninterrupted handshake
$proxy->serverflags("-min_protocol DTLSv1.3 -max_protocol DTLSv1.3");
$proxy->clientflags("-min_protocol DTLSv1.3 -max_protocol DTLSv1.3");
TLSProxy::Message->successondata(1);
ok($proxy->start(), "Proxy run succeeded");

my @expected = get_expected_ack_record_numbers();
my @actual = get_actual_acked_record_numbers();
my @missing = record_numbers_missing(\@expected, \@actual);
my $expected_count = @expected;
my $actual_count = @actual;
my $missing_count = @missing;

ok($missing_count == 0, "Check that all record numbers are acked");
ok($actual_count > 0, "Check that some record numbers are acked");
ok($expected_count > 0, "Check that some records to be acked were sent");

#Test 2: Check that records that are missing are not acked during a handshake
$proxy->clear();
my $found_first_new_session_ticket = 0;
$proxy->serverflags("-min_protocol DTLSv1.3 -max_protocol DTLSv1.3");
$proxy->clientflags("-min_protocol DTLSv1.3 -max_protocol DTLSv1.3");
$proxy->filter(\&drop_first_new_session_ticket_filter);
TLSProxy::Message->successondata(1);
ok($proxy->start(), "Proxy run succeeded");

@expected = get_expected_ack_record_numbers();
@actual = get_actual_acked_record_numbers();
@missing = record_numbers_missing(\@expected, \@actual);
$expected_count = @expected;
$actual_count = @actual;
$missing_count = @missing;

ok($missing_count == 1, "Check that all record numbers except one are acked");
ok($actual_count > 0, "Check that some record numbers are acked");
ok($expected_count > 0, "Check that some records to be acked were sent");

sub get_expected_ack_record_numbers
{
    my $records = $proxy->record_list;
    my @record_numbers = ();

    foreach (@{$records}) {
        my $record = $_;

        if ($record->content_type == TLSProxy::Record::RT_HANDSHAKE) {
            my $epoch = $record->epoch;
            my $seqnum = $record->seq;
            my $isdtls = $record->isdtls;
            my $isserver = $record->isserver;
            my $recnum = TLSProxy::RecordNumber->new($epoch, $seqnum);

            my @messages = TLSProxy::Message->get_messages($isserver, $record, $isdtls);

            my $record_should_be_acked = 0;

            foreach (@messages) {
                my $message = $_;
                if (($message->mt == TLSProxy::Message::MT_FINISHED && !$isserver)
                        || $message->mt == TLSProxy::Message::MT_KEY_UPDATE
                        || $message->mt == TLSProxy::Message::MT_NEW_SESSION_TICKET) {
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

        if ($record->content_type == TLSProxy::Record::RT_ACK) {
            my $idx;
            my $recnum_count = unpack('n', $record->decrypt_data);
            my $ptr = 2;

            next if ($recnum_count == 0);

            for ($idx = 0, $idx < $recnum_count, $idx++) {
                my $epoch_lo;
                my $epoch_hi;
                my $msgseq_lo;
                my $msgseq_hi;

                ($epoch_lo, $epoch_hi, $msgseq_lo, $msgseq_hi)
                    = unpack('NNNN', substr($record->decrypt_data, $ptr));
                $ptr = $ptr + 16;

                my $epoch = ($epoch_hi << 32) | $epoch_lo;
                my $msgseq = ($msgseq_hi << 32) | $msgseq_lo;
                my $recnum = TLSProxy::RecordNumber->new($epoch, $msgseq);

                push(@record_numbers, $recnum);
            }
        }
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

sub drop_first_new_session_ticket_filter
{
    my $proxy = shift;

    return if ($found_first_new_session_ticket == 1);

    foreach my $record (@{$proxy->record_list}) {
        next if ($record->{sent});

        my $isdtls = $record->isdtls;
        my $isserver = $record->isserver;
        my @messages = TLSProxy::Message->get_messages($isserver, $record, $isdtls);
        foreach my $message (@messages) {
            if ($message->mt == TLSProxy::Message::MT_NEW_SESSION_TICKET) {
                $record->{sent} = 1;
                $found_first_new_session_ticket = 1;
                last;
            }
        }
        last if $found_first_new_session_ticket == 1;
    }
}
