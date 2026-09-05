#! /usr/bin/env perl
# Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use File::Temp qw(tempfile);
use TLSProxy::Proxy;
use Cwd qw(abs_path);

my $test_name = "test_certtypeext";
setup($test_name);

$ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("test"));

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the module feature enabled"
    if disabled("module");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs TLSv1.2 enabled"
    if (disabled("tls1_2"));

plan skip_all => "$test_name needs TLSv1.3 enabled"
    if (disabled("tls1_3"));

my $cert_file = srctop_file("apps", "server.pem");
my $clnt_ca = srctop_file("test", "certs", "ca+clientAuth.pem");
my $key_file = srctop_file("test", "certs", "ee-key.pem");
my $clnt_ee = srctop_file("test", "certs", "ee-client.pem");

my $proxy = TLSProxy::Proxy->new(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    $cert_file,
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE}),
    have_IPv6()
);

# RPK-only server
my $proxy2 = TLSProxy::Proxy->new(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    undef,
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE}),
    have_IPv6()
);

# Did the given proxy see a handshake message of the given type?
sub saw_message
{
    my ($p, $mt) = @_;

    return scalar grep { $_->mt() == $mt } @{$p->message_list};
}

# Did the server send a fatal alert with the given description?
sub server_alert_is
{
    my $desc = shift;
    my $alert = TLSProxy::Message->alert();

    return defined $alert
        && $alert->server()
        && $alert->level() == TLSProxy::Message::AL_LEVEL_FATAL
        && $alert->description() == $desc;
}

# Does the given proxy's EncryptedExtensions carry server_cert_type?
sub ee_has_server_cert_type
{
    my $p = shift;
    my ($ee) = grep { $_->mt() == TLSProxy::Message::MT_ENCRYPTED_EXTENSIONS }
        @{$p->message_list};

    return defined $ee
        && defined $ee->extension_data->{TLSProxy::Message::EXT_SERVER_CERT_TYPE};
}

# Does the given proxy's ServerHello carry server_cert_type? (TLS 1.2)
sub sh_has_server_cert_type
{
    my $p = shift;
    my ($sh) = grep { $_->mt() == TLSProxy::Message::MT_SERVER_HELLO }
        @{$p->message_list};

    return defined $sh
        && defined $sh->extension_data->{TLSProxy::Message::EXT_SERVER_CERT_TYPE};
}

# Inject a malformed cert type extension into the ClientHello
my $garbage_ext;
my $garbage_payload;
sub garbage_filter
{
    my $p = shift;
    my $message;

    return if $p->flight != 0;

    $message = ${$p->message_list}[0];
    $message->set_extension($garbage_ext, $garbage_payload);
    $message->repack();
}

# Test 1: Client is X.509-only, server verifies client cert via key
$proxy->clear();
$proxy->clientflags("-key $key_file -cert $clnt_ee -verify_return_error -partial_chain -verifyCAfile $cert_file");
$proxy->serverflags("-Verify 1 -expected-rpks $key_file");
$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
plan tests => 19;
ok(TLSProxy::Message->success
        && saw_message($proxy, TLSProxy::Message::MT_CERTIFICATE_REQUEST),
    "Client cert RPK verify");

# Test 2: Client is X.509-only, server verifies client cert via PKI
$proxy->clear();
$proxy->clientflags("-key $key_file -cert $clnt_ee -verify_return_error -partial_chain -verifyCAfile $cert_file");
$proxy->serverflags("-Verify 1 -partial_chain -verifyCAfile $clnt_ca");
$proxy->start();
ok(TLSProxy::Message->success
        && saw_message($proxy, TLSProxy::Message::MT_CERTIFICATE_REQUEST),
    "Client cert X.509 verify");

# Test 3: Server is X.509-only, client verifies server cert via key
$proxy->clear();
$proxy->clientflags("-verify_return_error -expected-rpks $cert_file");
$proxy->serverflags("");
$proxy->start();
ok(TLSProxy::Message->success, "Server cert RPK verify");

# Test 4: Server is X.509-only, client verifies server cert as trusted
# Can't use CA trust here, the proxy modules break certificate signature algorithms.
$proxy->clear();
$proxy->clientflags("-verify_return_error -partial_chain -verifyCAfile $cert_file");
$proxy->serverflags("");
$proxy->start();
ok(TLSProxy::Message->success, "Server cert X.509 verify");

# Test 5: Client is RPK-only, server X.509-only, verification optional.
# The server must complete the handshake without a CertificateRequest.
$proxy->clear();
$proxy->clientflags("-enable_client_rpk -key $key_file -partial_chain -verifyCAfile $cert_file");
$proxy->serverflags("-verify 1");
$proxy->start();
ok(TLSProxy::Message->success
        && !saw_message($proxy, TLSProxy::Message::MT_CERTIFICATE_REQUEST),
    "Cert type mismatch suppresses optional client auth");

# Test 6: Server is RPK-only, client verifies RPK.
# The server must confirm RPK in EncryptedExtensions.
$proxy2->clear();
$proxy2->clientflags("-enable_server_rpk -verify_return_error -expected-rpks $cert_file");
$proxy2->serverflags("-key $cert_file -enable_server_rpk");
$proxy2->start();
ok(TLSProxy::Message->success && ee_has_server_cert_type($proxy2),
    "Server RPK supported by client");

# Test 7: Key-only server, client X.509-only.  With no usable identity
# for an implicit X.509 handshake, certificate selection fails with
# handshake_failure before any Certificate message.
$proxy2->clear();
$proxy2->clientflags("-key $key_file -cert $clnt_ee -partial_chain -verifyCAfile $cert_file");
$proxy2->serverflags("-key $cert_file -enable_server_rpk");
$proxy2->start();
ok(TLSProxy::Message->fail
        && server_alert_is(TLSProxy::Message::AL_DESC_HANDSHAKE_FAILURE)
        && !saw_message($proxy2, TLSProxy::Message::MT_CERTIFICATE),
    "Server RPK not supported by client");

# Test 8: Client is RPK-only, server is X.509-only, required verification
# fails with unsupported_certificate before any CertificateRequest.
$proxy->clear();
$proxy->clientflags("-enable_client_rpk -key $key_file -partial_chain -verifyCAfile $cert_file");
$proxy->serverflags("-Verify 1 -partial_chain -verifyCAfile $clnt_ca");
$proxy->start();
ok(TLSProxy::Message->fail
        && server_alert_is(TLSProxy::Message::AL_DESC_UNSUPPORTED_CERTIFICATE)
        && !saw_message($proxy, TLSProxy::Message::MT_CERTIFICATE_REQUEST),
    "Cert type mismatch fails mandatory client auth");

# Test 9: Mutual RPK-only authentication
$proxy2->clear();
$proxy2->clientflags("-enable_client_rpk -enable_server_rpk -key $key_file -verify_return_error -expected-rpks $cert_file");
$proxy2->serverflags("-key $cert_file -enable_server_rpk -enable_client_rpk -Verify 1 -expected-rpks $key_file");
$proxy2->start();
ok(TLSProxy::Message->success
        && saw_message($proxy2, TLSProxy::Message::MT_CERTIFICATE_REQUEST)
        && ee_has_server_cert_type($proxy2),
    "Mutual RPK-only authentication");

# Test 10: Mutual RPK-only authentication, TLS 1.2.
# The server must confirm RPK in the ServerHello.
$proxy2->clear();
$proxy2->clientflags("-tls1_2 -enable_client_rpk -enable_server_rpk -key $key_file -verify_return_error -expected-rpks $cert_file");
$proxy2->serverflags("-key $cert_file -enable_server_rpk -enable_client_rpk -Verify 1 -expected-rpks $key_file");
$proxy2->start();
ok(TLSProxy::Message->success
        && saw_message($proxy2, TLSProxy::Message::MT_CERTIFICATE_REQUEST)
        && sh_has_server_cert_type($proxy2),
    "Mutual RPK-only authentication TLS 1.2");

# Test 11: Client is RPK-only, server X.509-only, verification optional,
# TLS 1.2
$proxy->clear();
$proxy->clientflags("-tls1_2 -enable_client_rpk -key $key_file -partial_chain -verifyCAfile $cert_file");
$proxy->serverflags("-verify 1");
$proxy->start();
ok(TLSProxy::Message->success
        && !saw_message($proxy, TLSProxy::Message::MT_CERTIFICATE_REQUEST),
    "Cert type mismatch suppresses optional client auth TLS 1.2");

# Test 12: Client is RPK-only, server is X.509-only, required verification
# fails, TLS 1.2
$proxy->clear();
$proxy->clientflags("-tls1_2 -enable_client_rpk -key $key_file -partial_chain -verifyCAfile $cert_file");
$proxy->serverflags("-Verify 1 -partial_chain -verifyCAfile $clnt_ca");
$proxy->start();
ok(TLSProxy::Message->fail
        && server_alert_is(TLSProxy::Message::AL_DESC_UNSUPPORTED_CERTIFICATE)
        && !saw_message($proxy, TLSProxy::Message::MT_CERTIFICATE_REQUEST),
    "Cert type mismatch fails mandatory client auth TLS 1.2");

# Test 13: Key-only server, client X.509-only, TLS 1.2.  No usable
# identity means no shared cipher, and a handshake_failure alert.
$proxy2->clear();
$proxy2->clientflags("-tls1_2 -key $key_file -cert $clnt_ee -partial_chain -verifyCAfile $cert_file");
$proxy2->serverflags("-key $cert_file -enable_server_rpk");
$proxy2->start();
ok(TLSProxy::Message->fail
        && server_alert_is(TLSProxy::Message::AL_DESC_HANDSHAKE_FAILURE),
    "Server RPK not supported by client TLS 1.2");

# Test 14: A server with a certificate but an RPK-only type list has a
# usable identity, so the mismatch is caught at extension construction
# with unsupported_certificate.
$proxy->clear();
$proxy->clientflags("-partial_chain -verifyCAfile $cert_file");
$proxy->serverflags("-server_cert_type rpk");
$proxy->start();
ok(TLSProxy::Message->fail
        && server_alert_is(TLSProxy::Message::AL_DESC_UNSUPPORTED_CERTIFICATE)
        && !saw_message($proxy, TLSProxy::Message::MT_CERTIFICATE),
    "Certed RPK-only server, client without RPK");

# Test 15: same with TLS 1.2, the alert moves to ServerHello construction
$proxy->clear();
$proxy->clientflags("-tls1_2 -partial_chain -verifyCAfile $cert_file");
$proxy->serverflags("-server_cert_type rpk");
$proxy->start();
ok(TLSProxy::Message->fail
        && server_alert_is(TLSProxy::Message::AL_DESC_UNSUPPORTED_CERTIFICATE)
        && !saw_message($proxy, TLSProxy::Message::MT_CERTIFICATE),
    "Certed RPK-only server, client without RPK TLS 1.2");

# Test 16: Server is RPK-only, get a session
(undef, my $session) = tempfile();
$proxy2->clear();
$proxy2->clientflags("-enable_server_rpk -verify_return_error -expected-rpks $cert_file -sess_out $session");
$proxy2->serverflags("-key $cert_file -enable_server_rpk");
$proxy2->sessionfile($session);
$proxy2->start();
ok(TLSProxy::Message->success, "Server RPK initial session");

# Test 17: Resume the session.  No Certificate message flows, but the
# server still confirms RPK in EncryptedExtensions.
$proxy2->clear();
$proxy2->clientflags("-enable_server_rpk -verify_return_error -expected-rpks $cert_file -sess_in $session");
$proxy2->serverflags("-key $cert_file -enable_server_rpk");
$proxy2->start();
ok(TLSProxy::Message->success
        && !saw_message($proxy2, TLSProxy::Message::MT_CERTIFICATE)
        && ee_has_server_cert_type($proxy2),
    "Server RPK resumption");
unlink $session;

# Test 18: Empty client_cert_type list is a decode error
$proxy->clear();
$proxy->clientflags("-partial_chain -verifyCAfile $cert_file");
$proxy->serverflags("");
$garbage_ext = TLSProxy::Message::EXT_CLIENT_CERT_TYPE;
$garbage_payload = pack "C", 0x00;
$proxy->filter(\&garbage_filter);
$proxy->start();
ok(TLSProxy::Message->fail
        && server_alert_is(TLSProxy::Message::AL_DESC_DECODE_ERROR),
    "Empty client_cert_type list");

# Test 19: Truncated server_cert_type extension is a decode error
$proxy->clear();
$proxy->clientflags("-partial_chain -verifyCAfile $cert_file");
$proxy->serverflags("");
$garbage_ext = TLSProxy::Message::EXT_SERVER_CERT_TYPE;
$garbage_payload = "";
$proxy->filter(\&garbage_filter);
$proxy->start();
ok(TLSProxy::Message->fail
        && server_alert_is(TLSProxy::Message::AL_DESC_DECODE_ERROR),
    "Truncated server_cert_type extension");
