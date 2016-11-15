#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;
my $test_name = "test_tls13messages";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS|MSWin32)$/;

plan skip_all => "$test_name needs the dynamic engine feature enabled"
    if disabled("engine") || disabled("dynamic-engine");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs TLSv1.3 enabled"
    if disabled("tls1_3");

$ENV{OPENSSL_ia32cap} = '~0x200000200000000';

use constant {
    DEFAULT_HANDSHAKE => 1
};

my @handmessages = (
    [TLSProxy::Message::MT_CLIENT_HELLO, DEFAULT_HANDSHAKE],
    [TLSProxy::Message::MT_SERVER_HELLO, DEFAULT_HANDSHAKE],
    [TLSProxy::Message::MT_CERTIFICATE, DEFAULT_HANDSHAKE],
    [TLSProxy::Message::MT_FINISHED, DEFAULT_HANDSHAKE],
    [TLSProxy::Message::MT_FINISHED, DEFAULT_HANDSHAKE],
    [0, 0]
);

my $proxy = TLSProxy::Proxy->new(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

sub checkmessages($$);

#Test 1: Check we get all the right messages for a default handshake
$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
plan tests => 1;
checkmessages(DEFAULT_HANDSHAKE, "Default handshake test");

sub checkmessages($$)
{
    my ($handtype, $testname) = @_;

    subtest $testname => sub {
        my $loop = 0;
        my $numtests;

        #First count the number of tests
        for ($numtests = 1; $handmessages[$loop][1] != 0; $loop++) {
            $numtests++ if (($handmessages[$loop][1] & $handtype) != 0);
        }

        plan tests => $numtests;

        $loop = 0;
        foreach my $message (@{$proxy->message_list}) {
            for (; $handmessages[$loop][1] != 0
                   && ($handmessages[$loop][1] & $handtype) == 0; $loop++) {
                next;
            }
            ok($handmessages[$loop][1] != 0
               && $message->mt == $handmessages[$loop][0],
               "Message type check. Got ".$message->mt
               .", expected ".$handmessages[$loop][0]);
            $loop++;
        }
        ok($handmessages[$loop][1] == 0, "All expected messages processed");
    }
}
