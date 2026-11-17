#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
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

my $test_name = "test_tls13certwithexternpsk";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the module feature enabled"
    if disabled("module");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs TLSv1.3 enabled"
    if disabled("tls1_3");

plan skip_all => "$test_name needs elliptic curves enabled"
    if disabled("ec");

$ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("test"));

# The RFC 9973 "tls_cert_with_extern_psk" extension. Successful handshakes are
# tested in sslapitest, this tests how peers deal with protocol violations.

use constant {
    NO_MODIFICATION => 0,
    ADD_EARLY_DATA_TO_CH => 1,
    ADD_EXT_TO_CH => 2,
    ADD_EXT_TO_SH => 3,
    DELETE_KEY_SHARE_FROM_SH => 4,
    ADD_EXT_TO_HRR => 5,
    ADD_EXT_TO_CH_EXTERNAL_PSK_FIRST => 6,
    SET_EXT_DATA_IN_CH => 7,
    ADD_EXT_TO_CH_PSK_KE_ONLY => 8,
    ADD_EARLY_DATA_TO_CH_BAD_PSK => 9,
    CORRUPT_BINDER_IN_CH => 10,
    ADD_EXT_TO_CH_AFTER_UNKNOWN_PSKS => 11,
    SET_EXT_DATA_IN_SH => 12
};

my $testtype = NO_MODIFICATION;
my $psk = "-psk 0123456789abcdef0123456789abcdef";
my $cwep = "-cert_with_extern_psk";
# Both PSKs must use the same hash for the client to offer them together
my $sha256 = "-ciphersuites TLS_AES_128_GCM_SHA256";
# The number of PSKs offered in the first ClientHello
my $psk_count = 0;
# The number of identities the server examines at most
my $max_psks = 16;

my $proxy = TLSProxy::Proxy->new(
    \&modify_filter,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE}),
    have_IPv6()
);

#Test 1: The external PSK is used, but the server still authenticates with its
#        certificate
$proxy->clientflags("$psk $cwep");
$proxy->serverflags("$psk $cwep");
$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
plan tests => 18;
ok(TLSProxy::Message->success() && is_cert_with_extern_psk_handshake(),
   "Certificate with external PSK");

#Test 2: The server must refuse early data along with the extension, here with
#        a PSK it doesn't know
$proxy->clear();
$proxy->clientflags("$psk $cwep");
$proxy->serverflags($cwep);
$testtype = ADD_EARLY_DATA_TO_CH;
$proxy->start();
ok(is_alert(1, TLSProxy::Message::AL_DESC_ILLEGAL_PARAMETER),
   "Extension with early data");

#Test 3: The server must refuse a resumption PSK along with the extension
start_with_resumption_psk(ADD_EXT_TO_CH);
ok(is_alert(1, TLSProxy::Message::AL_DESC_ILLEGAL_PARAMETER),
   "Extension with a resumption PSK");

#Test 4: Likewise if the client offers the resumption PSK followed by an
#        external PSK the server knows
start_with_resumption_and_external_psk(ADD_EXT_TO_CH);
ok(is_alert(1, TLSProxy::Message::AL_DESC_ILLEGAL_PARAMETER)
   && $psk_count == 2,
   "Extension with a resumption PSK, then an external PSK");

#Test 5: Likewise if the external PSK comes first, so the server selects it
#        before it gets to the resumption PSK
start_with_resumption_and_external_psk(ADD_EXT_TO_CH_EXTERNAL_PSK_FIRST);
ok(is_alert(1, TLSProxy::Message::AL_DESC_ILLEGAL_PARAMETER)
   && $psk_count == 2,
   "Extension with an external PSK, then a resumption PSK");

#Test 6: The client must refuse the extension unless the server selects its
#        PSK
$proxy->clear();
$proxy->clientflags("$psk $cwep");
$testtype = ADD_EXT_TO_SH;
$proxy->start();
ok(is_alert(0, TLSProxy::Message::AL_DESC_ILLEGAL_PARAMETER),
   "Extension without PSK");

#Test 7: The client must refuse the extension without a key_share, even if it
#        allows psk_ke otherwise
$proxy->clear();
$proxy->clientflags("$psk $cwep -allow_no_dhe_kex");
$proxy->serverflags("$psk $cwep");
$testtype = DELETE_KEY_SHARE_FROM_SH;
$proxy->start();
ok(is_alert(0, TLSProxy::Message::AL_DESC_MISSING_EXTENSION),
   "Extension without key_share");

#Test 8: The client must refuse the extension in a HelloRetryRequest
$proxy->clear();
$proxy->clientflags("$psk $cwep");
$proxy->serverflags("$psk $cwep -curves P-384");
$testtype = ADD_EXT_TO_HRR;
$proxy->start();
ok(is_alert(0, TLSProxy::Message::AL_DESC_ILLEGAL_PARAMETER),
   "Extension in HelloRetryRequest");

#Test 9: The server checks the extension before the PSKs, so it refuses early
#        data along with it even if the pre_shared_key extension is malformed
$proxy->clear();
$proxy->clientflags("$psk $cwep");
$proxy->serverflags("$psk $cwep");
$testtype = ADD_EARLY_DATA_TO_CH_BAD_PSK;
$proxy->start();
ok(is_alert(1, TLSProxy::Message::AL_DESC_ILLEGAL_PARAMETER),
   "Extension with early data and a malformed PSK extension");

#Test 10: Likewise it refuses a non-empty extension even along with a
#         resumption PSK
start_with_resumption_psk(SET_EXT_DATA_IN_CH);
ok(is_alert(1, TLSProxy::Message::AL_DESC_DECODE_ERROR),
   "Extension with data");

#Test 11: The server must refuse a resumption PSK along with the extension
#         even without psk_dhe_ke, when it uses no PSK at all
start_with_resumption_psk(ADD_EXT_TO_CH_PSK_KE_ONLY);
ok(is_alert(1, TLSProxy::Message::AL_DESC_ILLEGAL_PARAMETER),
   "Extension with a resumption PSK, without psk_dhe_ke");

#Test 12: The client must refuse a server that acknowledges the extension, but
#         then skips its Certificate and CertificateVerify
$proxy->clear();
$proxy->clientflags("$psk $cwep");
$proxy->serverflags($psk);
$testtype = ADD_EXT_TO_SH;
$proxy->start();
ok(is_alert(0, TLSProxy::Message::AL_DESC_UNEXPECTED_MESSAGE),
   "Extension without Certificate");

#Test 13: If the binder doesn't verify, the server must abort with
#         illegal_parameter rather than decrypt_error
$proxy->clear();
$proxy->clientflags("$psk $cwep");
$proxy->serverflags("$psk $cwep");
$testtype = CORRUPT_BINDER_IN_CH;
$proxy->start();
ok(is_alert(1, TLSProxy::Message::AL_DESC_ILLEGAL_PARAMETER),
   "Extension with a bad binder");

#Test 14: Without the extension it is still decrypt_error
$proxy->clear();
$proxy->clientflags($psk);
$proxy->serverflags($psk);
$testtype = CORRUPT_BINDER_IN_CH;
$proxy->start();
ok(is_alert(1, TLSProxy::Message::AL_DESC_DECRYPT_ERROR),
   "Bad binder without the extension");

#Test 15: The server must refuse a resumption PSK along with the extension even
#         if it comes after as many other PSKs as the server examines
start_with_resumption_psk(ADD_EXT_TO_CH_AFTER_UNKNOWN_PSKS);
ok(is_alert(1, TLSProxy::Message::AL_DESC_ILLEGAL_PARAMETER)
   && $psk_count == $max_psks + 1,
   "Extension with a resumption PSK after $max_psks unknown PSKs");

#Test 16: The client must abort if a HelloRetryRequest selects a ciphersuite
#         that doesn't match the PSK's hash, as it has to repeat the extension
#         with the PSK
$proxy->clear();
$proxy->clientflags("$psk $cwep");
$proxy->serverflags("$cwep -ciphersuites TLS_AES_256_GCM_SHA384 -curves P-384");
$testtype = NO_MODIFICATION;
$proxy->start();
ok(is_alert(0, TLSProxy::Message::AL_DESC_HANDSHAKE_FAILURE),
   "HelloRetryRequest with a ciphersuite of another hash");

#Test 17: The server must refuse an offer with more PSKs than it examines, even
#         if none of them is a resumption PSK
$proxy->clear();
$proxy->clientflags("$psk $cwep");
$proxy->serverflags("$psk $cwep");
$testtype = ADD_EXT_TO_CH_AFTER_UNKNOWN_PSKS;
$proxy->start();
ok(is_alert(1, TLSProxy::Message::AL_DESC_ILLEGAL_PARAMETER)
   && $psk_count == $max_psks + 1,
   "Extension with an external PSK after $max_psks unknown PSKs");

#Test 18: The client must refuse a non-empty extension in the ServerHello
$proxy->clear();
$proxy->clientflags("$psk $cwep");
$proxy->serverflags("$psk $cwep");
$testtype = SET_EXT_DATA_IN_SH;
$proxy->start();
ok(is_alert(0, TLSProxy::Message::AL_DESC_DECODE_ERROR),
   "Extension with data in the ServerHello");

# Get a session from a server, then reconnect with it, using |$type| to modify
# the ClientHello
sub start_with_resumption_psk
{
    my $type = shift;

    $proxy->clear();
    (undef, my $session) = tempfile();
    $proxy->serverconnects(2);
    $proxy->clientflags("-sess_out $session");
    $proxy->serverflags($cwep);
    $proxy->sessionfile($session);
    $testtype = NO_MODIFICATION;
    $proxy->start();
    $proxy->clearClient();
    $proxy->clientflags("-sess_in $session");
    $testtype = $type;
    $proxy->clientstart();
    unlink $session;
}

# Get a session from a server that knows the external PSK, then reconnect
# offering both that session and the external PSK. The client doesn't offer the
# external PSK when resuming with the extension, so add the extension to its
# ClientHello instead, using |$type| to modify it.
sub start_with_resumption_and_external_psk
{
    my $type = shift;

    $proxy->clear();
    (undef, my $session) = tempfile();
    $proxy->serverconnects(2);
    $proxy->clientflags("-sess_out $session $sha256");
    $proxy->serverflags("$psk $cwep");
    $proxy->sessionfile($session);
    $testtype = NO_MODIFICATION;
    $psk_count = 0;
    $proxy->start();
    $proxy->clearClient();
    $proxy->clientflags("-sess_in $session $psk $sha256");
    $testtype = $type;
    $proxy->clientstart();
    unlink $session;
}

sub is_cert_with_extern_psk_handshake
{
    my ($sh, $cert, $cert_verify);

    foreach my $message (@{$proxy->message_list}) {
        $sh = $message if $message->mt == TLSProxy::Message::MT_SERVER_HELLO;
        next if !$message->server();
        $cert = 1 if $message->mt == TLSProxy::Message::MT_CERTIFICATE;
        $cert_verify = 1
            if $message->mt == TLSProxy::Message::MT_CERTIFICATE_VERIFY;
    }

    return defined $sh
        && defined ${$sh->extension_data}{TLSProxy::Message::EXT_CERT_WITH_EXTERN_PSK}
        && defined ${$sh->extension_data}{TLSProxy::Message::EXT_PSK}
        && $cert && $cert_verify;
}

sub is_alert
{
    my ($from_server, $description) = @_;
    my $alert;

    return 0 unless TLSProxy::Message->fail();
    $alert = TLSProxy::Message->alert();

    return defined $alert
        && ($alert->server() ? 1 : 0) == $from_server
        && $alert->description() == $description;
}

sub modify_filter
{
    my $proxy = shift;
    my $message;

    if ($testtype == ADD_EARLY_DATA_TO_CH || $testtype == ADD_EXT_TO_CH
        || $testtype == ADD_EXT_TO_CH_EXTERNAL_PSK_FIRST
        || $testtype == SET_EXT_DATA_IN_CH
        || $testtype == ADD_EXT_TO_CH_PSK_KE_ONLY
        || $testtype == ADD_EARLY_DATA_TO_CH_BAD_PSK
        || $testtype == CORRUPT_BINDER_IN_CH
        || $testtype == ADD_EXT_TO_CH_AFTER_UNKNOWN_PSKS) {
        # Only modify the first ClientHello
        return if $proxy->flight != 0;
        $message = ${$proxy->message_list}[0];
        return if !defined $message
                  || $message->mt != TLSProxy::Message::MT_CLIENT_HELLO;

        my ($identities, $binders) =
            split_psk_ext(${$message->extension_data}{TLSProxy::Message::EXT_PSK});
        $psk_count = scalar @$identities;

        if ($testtype == ADD_EARLY_DATA_TO_CH
            || $testtype == ADD_EARLY_DATA_TO_CH_BAD_PSK) {
            $message->set_extension(TLSProxy::Message::EXT_EARLY_DATA, "");
        } elsif ($testtype == SET_EXT_DATA_IN_CH) {
            $message->set_extension(
                TLSProxy::Message::EXT_CERT_WITH_EXTERN_PSK, "\x00");
        } elsif ($testtype != CORRUPT_BINDER_IN_CH) {
            $message->set_extension(
                TLSProxy::Message::EXT_CERT_WITH_EXTERN_PSK, "");
        }
        if ($testtype == ADD_EXT_TO_CH_PSK_KE_ONLY) {
            # Offer psk_ke only
            $message->set_extension(TLSProxy::Message::EXT_PSK_KEX_MODES,
                pack("C2", 1, 0));
        }
        if ($testtype == ADD_EARLY_DATA_TO_CH_BAD_PSK) {
            # Drop the binders
            my $ids = join("", @$identities);

            $message->set_extension(TLSProxy::Message::EXT_PSK,
                pack("n", length($ids)) . $ids);
        }
        if ($testtype == CORRUPT_BINDER_IN_CH) {
            # Flip a bit in the last binder
            my $ids = join("", @$identities);
            my $bnds = join("", @$binders);

            substr($bnds, -1, 1) ^= "\x01";
            $message->set_extension(TLSProxy::Message::EXT_PSK,
                pack("n", length($ids)) . $ids
                . pack("n", length($bnds)) . $bnds);
        }
        if ($testtype == ADD_EXT_TO_CH_AFTER_UNKNOWN_PSKS) {
            # Put PSKs the server doesn't know before the resumption PSK
            my @unknown = (1 .. $max_psks);
            my $ids = join("",
                (map { pack("n", 16) . sprintf("unknown psk %4d", $_)
                       . pack("N", 0) } @unknown),
                @$identities);
            my $bnds = join("",
                (map { pack("C", 32) . ("\x00" x 32) } @unknown), @$binders);

            $psk_count += $max_psks;
            $message->set_extension(TLSProxy::Message::EXT_PSK,
                pack("n", length($ids)) . $ids
                . pack("n", length($bnds)) . $bnds);
        }
        if ($testtype == ADD_EXT_TO_CH_EXTERNAL_PSK_FIRST) {
            # OpenSSL offers its resumption PSK first, so swap them around
            my $ids = join("", reverse @$identities);
            my $bnds = join("", reverse @$binders);

            $message->set_extension(TLSProxy::Message::EXT_PSK,
                pack("n", length($ids)) . $ids
                . pack("n", length($bnds)) . $bnds);
        }
        $message->repack();
    } elsif ($testtype == ADD_EXT_TO_SH || $testtype == SET_EXT_DATA_IN_SH
             || $testtype == DELETE_KEY_SHARE_FROM_SH
             || $testtype == ADD_EXT_TO_HRR) {
        # Only modify the first ServerHello, or the HelloRetryRequest
        return if $proxy->flight != 1;
        $message = ${$proxy->message_list}[1];
        return if !defined $message
                  || $message->mt != TLSProxy::Message::MT_SERVER_HELLO;

        if ($testtype == DELETE_KEY_SHARE_FROM_SH) {
            $message->delete_extension(TLSProxy::Message::EXT_KEY_SHARE);
        } else {
            $message->set_extension(
                TLSProxy::Message::EXT_CERT_WITH_EXTERN_PSK,
                $testtype == SET_EXT_DATA_IN_SH ? "\x00" : "");
        }
        $message->repack();
    }
}

# Split the contents of a pre_shared_key extension in a ClientHello into its
# PskIdentity and PskBinderEntry entries
sub split_psk_ext
{
    my $data = shift;
    my (@identities, @binders);

    return (\@identities, \@binders) if !defined $data;

    my $identities = substr($data, 2, unpack("n", $data));
    my $binders = substr($data, 2 + length($identities) + 2);

    while (length($identities) > 0) {
        # The identity, followed by obfuscated_ticket_age
        push @identities,
            substr($identities, 0, 2 + unpack("n", $identities) + 4, "");
    }
    while (length($binders) > 0) {
        push @binders, substr($binders, 0, 1 + unpack("C", $binders), "");
    }

    return (\@identities, \@binders);
}
