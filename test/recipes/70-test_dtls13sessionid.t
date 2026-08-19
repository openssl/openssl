#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# In DTLS 1.3 OpenSSL client always sends an empty legacy_session_id. Other
# implementations (e.g. wolfSSL) instead send a non-empty legacy_session_id on
# the resumption ClientHello. The server must ignore that field for (D)TLS 1.3
# and resume regardless.
#
# This test drives an OpenSSL <-> OpenSSL DTLS 1.3 resumption through TLSProxy
# and injects a non-empty, mismatching legacy_session_id into the resumption
# ClientHello to reproduce that peer behaviour, then checks the server still
# resumes.  Resumption is detected by the absence of a server Certificate
# message (a full handshake would send one, a resumed handshake would not).

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use File::Temp qw(tempfile);
use TLSProxy::Proxy;
use TLSProxy::Message;
use Cwd qw(abs_path);

my $test_name = "test_dtls13sessionid";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS|MSWin32)$/;

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

plan tests => 2;

# P-256 only: keeps the ClientHello small enough to avoid DTLS fragmentation.
my $clientflags = "-min_protocol DTLSv1.3 -max_protocol DTLSv1.3 -groups ?P-256";
my $serverflags = "-min_protocol DTLSv1.3 -max_protocol DTLSv1.3";
(undef, my $session) = tempfile();

# Connection 1: full handshake that establishes and saves a resumable session.
$proxy->clientflags("$clientflags -sess_out $session");
$proxy->serverflags($serverflags);
$proxy->sessionfile($session);
TLSProxy::Message->successondata(1);
my $started = $proxy->start();
ok($started && server_sent_certificate(),
   "Initial DTLS 1.3 handshake completes and establishes a session");

# Connection 2: resume, but rewrite the resumption ClientHello to carry a
# non-empty, mismatching legacy_session_id (as a non-OpenSSL peer would).
$proxy->clear();
$proxy->clientflags("$clientflags -sess_in $session");
$proxy->serverflags($serverflags);
$proxy->sessionfile($session);
$proxy->filter(\&inject_session_id_filter);
TLSProxy::Message->successondata(1);
$proxy->start();
ok(TLSProxy::Message->success() && !server_sent_certificate(),
   "Server resumes despite a non-empty mismatching legacy_session_id");

unlink $session;

# Returns 1 if the server sent a Certificate message, i.e. a full (non-resumed)
# handshake took place.
sub server_sent_certificate
{
    foreach my $message (@{$proxy->message_list}) {
        return 1 if defined $message
                    && $message->server
                    && $message->mt == TLSProxy::Message::MT_CERTIFICATE;
    }
    return 0;
}

# Give every empty client ClientHello a non-empty legacy_session_id.  This grows
# the message by 32 bytes; the value deliberately does not match the cached
# session id, which is exactly the case ssl_get_prev_session() must tolerate for
# DTLS 1.3.
sub inject_session_id_filter
{
    my $proxy = shift;

    foreach my $message (@{$proxy->message_list}) {
        next if !defined $message
                || $message->mt != TLSProxy::Message::MT_CLIENT_HELLO;
        next if $message->session_id_len != 0;
        $message->session_id_len(32);
        $message->session(pack("C*", (0xAB) x 32));
        $message->repack();
    }
}
