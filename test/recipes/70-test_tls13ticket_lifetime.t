#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;
use File::Temp qw(tempfile);
use Cwd qw(abs_path);

package TLSProxy::RawNewSessionTicket;

use vars '@ISA';
push @ISA, 'TLSProxy::NewSessionTicket';

# Preserve the TLS 1.3 NewSessionTicket body set by the test filter.
sub set_message_contents
{
}

package main;

my $test_name = "test_tls13ticket_lifetime";
setup($test_name);

$ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("test"));

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the module feature enabled"
    if disabled("module");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs TLSv1.3 enabled"
    if disabled("tls1_3") || (disabled("ec") && disabled("dh"));

use constant ONE_WEEK_SEC => 7 * 24 * 60 * 60;

my $ticket_lifetime;

sub oversized_ticket_lifetime_filter
{
    my $proxy = shift;

    foreach my $message (@{$proxy->message_list}) {
        next if $message->mt != TLSProxy::Message::MT_NEW_SESSION_TICKET;

        my $data = $message->data;

        substr($data, 0, 4, pack('N', $ticket_lifetime));
        $message->data($data);
        bless $message, 'TLSProxy::RawNewSessionTicket';
        $message->repack();
    }
}

plan tests => 2;

my $proxy = TLSProxy::Proxy->new(
    \&oversized_ticket_lifetime_filter,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE}),
    have_IPv6()
);

test_ticket_lifetime($proxy, ONE_WEEK_SEC, ONE_WEEK_SEC,
    "Ticket lifetime at the limit is unchanged");
$proxy->clear();
test_ticket_lifetime($proxy, ONE_WEEK_SEC + 1, ONE_WEEK_SEC,
    "Ticket lifetime above the limit is capped");

sub test_ticket_lifetime
{
    my ($proxy, $sent_lifetime, $stored_lifetime, $name) = @_;
    my $stored_lifetime_hex = sprintf('%X', $stored_lifetime);

    subtest $name => sub {
        (undef, my $session) = tempfile();

        plan tests => 2;
        $ticket_lifetime = $sent_lifetime;
        $proxy->clientflags("-sess_out " . $session);
        $proxy->sessionfile($session);

        ok($proxy->start() && TLSProxy::Message->success(),
            "TLS 1.3 handshake succeeds");

        my $session_asn1 = join('', run(app([
            "openssl", "asn1parse", "-in", $session
        ]), capture => 1));

        like($session_asn1,
            qr/cont \[ 9 \].*?INTEGER\s+:0*\Q$stored_lifetime_hex\E\b/s,
            "Client stores the expected ticket lifetime hint");

        unlink $session;
    };
}
