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
use TLSProxy::Proxy;
use Cwd qw(abs_path);

my $test_name = "test_tls13certauth";
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

my $proxy = TLSProxy::Proxy->new(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

my $cafile = srctop_file("test", "certs", "rootcert.pem");
my $clientcert = srctop_file("apps", "server.pem");
my $empty_ca_list = pack("n", 0);

use constant {
    INJECT_NONE => 0,
    INJECT_CLIENT_HELLO => 1,
    INJECT_CERT_REQUEST => 2
};
my $testtype;

plan tests => 5;

#Test 1: An empty certificate_authorities list in the ClientHello is rejected
$testtype = INJECT_CLIENT_HELLO;
$proxy->filter(\&inject_filter);
$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
my $alert = TLSProxy::Message->alert();
ok(TLSProxy::Message->fail()
   && defined($alert)
   && $alert->server()
   && $alert->description() == TLSProxy::Message::AL_DESC_DECODE_ERROR,
   "Empty certificate_authorities in ClientHello");

#Test 2: An empty certificate_authorities list in the CertificateRequest is
#        rejected
$proxy->clear();
$testtype = INJECT_CERT_REQUEST;
$proxy->clientflags("-cert $clientcert");
$proxy->serverflags("-verify 5");
$proxy->start();
$alert = TLSProxy::Message->alert();
ok(TLSProxy::Message->fail()
   && defined($alert)
   && !$alert->server()
   && $alert->description() == TLSProxy::Message::AL_DESC_DECODE_ERROR,
   "Empty certificate_authorities in CertificateRequest");

#Test 3: A server with a CA list sends certificate_authorities
$proxy->clear();
$testtype = INJECT_NONE;
$proxy->clientflags("-cert $clientcert");
$proxy->serverflags("-verify 5 -CAfile $cafile");
$proxy->start();
ok(TLSProxy::Message->success() && cr_has_ca_ext() == 1,
   "certificate_authorities sent with a CA list");

#Test 4: With -no_ca_names the server must not send an empty list
$proxy->clear();
$proxy->clientflags("-cert $clientcert");
$proxy->serverflags("-verify 5 -CAfile $cafile -no_ca_names");
$proxy->start();
ok(TLSProxy::Message->success() && cr_has_ca_ext() == 0,
   "No empty certificate_authorities sent with -no_ca_names");

#Test 5: An empty CA list in a TLSv1.2 CertificateRequest is still accepted
SKIP: {
    skip "TLSv1.2 disabled", 1 if disabled("tls1_2");
    $proxy->clear();
    $proxy->clientflags("-tls1_2 -cert $clientcert");
    $proxy->serverflags("-verify 5 -no_ca_names");
    $proxy->start();
    ok(TLSProxy::Message->success(),
       "Empty CA list in TLSv1.2 CertificateRequest");
}

sub cr_has_ca_ext
{
    foreach my $message (@{$proxy->message_list}) {
        if ($message->mt == TLSProxy::Message::MT_CERTIFICATE_REQUEST) {
            return defined(${$message->extension_data}
                {TLSProxy::Message::EXT_CERTIFICATE_AUTHORITIES}) ? 1 : 0;
        }
    }
    return -1;
}

sub inject_filter
{
    my $proxy = shift;

    if ($testtype == INJECT_CLIENT_HELLO && $proxy->flight == 0) {
        my $message = ${$proxy->message_list}[0];

        $message->set_extension(TLSProxy::Message::EXT_CERTIFICATE_AUTHORITIES,
                                $empty_ca_list);
        $message->repack();
    } elsif ($testtype == INJECT_CERT_REQUEST && $proxy->flight == 1) {
        foreach my $message (@{$proxy->message_list}) {
            next if $message->mt != TLSProxy::Message::MT_CERTIFICATE_REQUEST;
            $message->set_extension(
                TLSProxy::Message::EXT_CERTIFICATE_AUTHORITIES,
                $empty_ca_list);
            $message->repack();
        }
    }
}
