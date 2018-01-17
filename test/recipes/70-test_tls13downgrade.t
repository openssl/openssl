#! /usr/bin/env perl
# Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;

my $test_name = "test_tls13downgrade";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the dynamic engine feature enabled"
    if disabled("engine") || disabled("dynamic-engine");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs TLS1.3 and TLS1.2 enabled"
    if disabled("tls1_3") || disabled("tls1_2");

# TODO(TLS1.3): Enable this when TLSv1.3 comes out of draft
plan skip_all => "$test_name not run in pre TLSv1.3 RFC implementation"
    if disabled("tls13downgrade");

$ENV{OPENSSL_ia32cap} = '~0x200000200000000';

my $proxy = TLSProxy::Proxy->new(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

use constant {
    DOWNGRADE_TO_TLS_1_2 => 0,
    DOWNGRADE_TO_TLS_1_1 => 1
};

#Test 1: Downgrade from TLSv1.3 to TLSv1.2
$proxy->filter(\&downgrade_filter);
my $testtype = DOWNGRADE_TO_TLS_1_2;
$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
plan tests => 3;
ok(TLSProxy::Message->fail(), "Downgrade TLSv1.3 to TLSv1.2");

#Test 2: Downgrade from TLSv1.3 to TLSv1.1
$proxy->clear();
$testtype = DOWNGRADE_TO_TLS_1_1;
$proxy->start();
ok(TLSProxy::Message->fail(), "Downgrade TLSv1.3 to TLSv1.1");

#Test 3: Downgrade from TLSv1.2 to TLSv1.1
$proxy->clear();
$proxy->clientflags("-no_tls1_3");
$proxy->serverflags("-no_tls1_3");
$proxy->start();
ok(TLSProxy::Message->fail(), "Downgrade TLSv1.2 to TLSv1.1");

sub downgrade_filter
{
    my $proxy = shift;

    # We're only interested in the initial ClientHello
    if ($proxy->flight != 0) {
        return;
    }

    my $message = ${$proxy->message_list}[0];

    my $ext;
    if ($testtype == DOWNGRADE_TO_TLS_1_2) {
        $ext = pack "C3",
            0x02, # Length
            0x03, 0x03; #TLSv1.2
    } else {
        $ext = pack "C3",
            0x02, # Length
            0x03, 0x02; #TLSv1.1
    }

    $message->set_extension(TLSProxy::Message::EXT_SUPPORTED_VERSIONS, $ext);

    $message->repack();
}

