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

plan skip_all => "$test_name needs TLS enabled"
    if alldisabled(available_protocols("tls"));

$ENV{OPENSSL_ia32cap} = '~0x200000200000000';
my $proxy = TLSProxy::Proxy->new(
    \&add_empty_recs_filter,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

plan tests => 3;

#Test 1: Injecting out of context empty records should fail
my $content_type = TLSProxy::Record::RT_APPLICATION_DATA;
my $inject_recs_num = 1;
$proxy->start();
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
