#!/usr/bin/perl
# Written by Stephen Henson for the OpenSSL project.
# ====================================================================
# Copyright (c) 1998-2015 The OpenSSL Project.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. All advertising materials mentioning features or use of this
#    software must display the following acknowledgment:
#    "This product includes software developed by the OpenSSL Project
#    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
#
# 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission. For written permission, please contact
#    openssl-core@openssl.org.
#
# 5. Products derived from this software may not be called "OpenSSL"
#    nor may "OpenSSL" appear in their names without prior written
#    permission of the OpenSSL Project.
#
# 6. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by the OpenSSL Project
#    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
#
# THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
# EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
# ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
# ====================================================================
#
# This product includes cryptographic software written by Eric Young
# (eay@cryptsoft.com).  This product includes software written by Tim
# Hudson (tjh@cryptsoft.com).

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;
use File::Temp qw(tempfile);

my $test_name = "test_tlsextms";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS|MSWin32)$/;

plan skip_all => "$test_name needs the dynamic engine feature enabled"
    if disabled("engine") || disabled("dynamic-engine");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

$ENV{OPENSSL_ia32cap} = '~0x200000200000000';

sub checkmessages($$$$$);
sub setrmextms($$);
sub clearall();

my $crmextms = 0;
my $srmextms = 0;
my $cextms = 0;
my $sextms = 0;
my $fullhand = 0;

my $proxy = TLSProxy::Proxy->new(
    \&extms_filter,
    cmdstr(app(["openssl"])),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

plan tests => 9;

#Test 1: By default server and client should send extended master secret
# extension.
#Expected result: ClientHello extension seen; ServerHello extension seen
#                 Full handshake

setrmextms(0, 0);
$proxy->start();
checkmessages(1, "Default extended master secret test", 1, 1, 1);

#Test 2: If client omits extended master secret extension, server should too.
#Expected result: ClientHello extension not seen; ServerHello extension not seen
#                 Full handshake

clearall();
setrmextms(1, 0);
$proxy->start();
checkmessages(2, "No client extension extended master secret test", 0, 0, 1);

# Test 3: same as 1 but with session tickets disabled.
# Expected result: same as test 1.

clearall();
$proxy->clientflags("-no_ticket");
setrmextms(0, 0);
$proxy->start();
checkmessages(3, "No ticket extended master secret test", 1, 1, 1);

# Test 4: same as 2 but with session tickets disabled.
# Expected result: same as test 2.

clearall();
$proxy->clientflags("-no_ticket");
setrmextms(1, 0);
$proxy->start();
checkmessages(2, "No ticket, no client extension extended master secret test", 0, 0, 1);

#Test 5: Session resumption extended master secret test
#
#Expected result: ClientHello extension seen; ServerHello extension seen
#                 Abbreviated handshake

clearall();
setrmextms(0, 0);
(my $fh, my $session) = tempfile();
$proxy->serverconnects(2);
$proxy->clientflags("-sess_out ".$session);
$proxy->start();
$proxy->clearClient();
$proxy->clientflags("-sess_in ".$session);
$proxy->clientstart();
checkmessages(5, "Session resumption extended master secret test", 1, 1, 0);

#Test 6: Session resumption extended master secret test original session
# omits extension. Server must not resume session.
#Expected result: ClientHello extension seen; ServerHello extension seen
#                 Full handshake

clearall();
setrmextms(1, 0);
($fh, $session) = tempfile();
$proxy->serverconnects(2);
$proxy->clientflags("-sess_out ".$session);
$proxy->start();
$proxy->clearClient();
$proxy->clientflags("-sess_in ".$session);
setrmextms(0, 0);
$proxy->clientstart();
checkmessages(6, "Session resumption extended master secret test", 1, 1, 1);

#Test 7: Session resumption extended master secret test resumed session
# omits client extension. Server must abort connection.
#Expected result: aborted connection.

clearall();
setrmextms(0, 0);
($fh, $session) = tempfile();
$proxy->serverconnects(2);
$proxy->clientflags("-sess_out ".$session);
$proxy->start();
$proxy->clearClient();
$proxy->clientflags("-sess_in ".$session);
setrmextms(1, 0);
$proxy->clientstart();
ok(TLSProxy::Message->fail(), "Client inconsistent session resumption");

#Test 8: Session resumption extended master secret test resumed session
# omits server extension. Client must abort connection.
#Expected result: aborted connection.

clearall();
setrmextms(0, 0);
($fh, $session) = tempfile();
$proxy->serverconnects(2);
$proxy->clientflags("-sess_out ".$session);
$proxy->start();
$proxy->clearClient();
$proxy->clientflags("-sess_in ".$session);
setrmextms(0, 1);
$proxy->clientstart();
ok(TLSProxy::Message->fail(), "Server inconsistent session resumption 1");

#Test 9: Session resumption extended master secret test initial session
# omits server extension. Client must abort connection.
#Expected result: aborted connection.

clearall();
setrmextms(0, 1);
($fh, $session) = tempfile();
$proxy->serverconnects(2);
$proxy->clientflags("-sess_out ".$session);
$proxy->start();
$proxy->clearClient();
$proxy->clientflags("-sess_in ".$session);
setrmextms(0, 0);
$proxy->clientstart();
ok(TLSProxy::Message->fail(), "Server inconsistent session resumption 2");

sub extms_filter
{
    my $proxy = shift;

    foreach my $message (@{$proxy->message_list}) {
        if ($crmextms && $message->mt == TLSProxy::Message::MT_CLIENT_HELLO) {
            $message->delete_extension(TLSProxy::Message::EXT_EXTENDED_MASTER_SECRET);
            $message->repack();
        }
        if ($srmextms && $message->mt == TLSProxy::Message::MT_SERVER_HELLO) {
            $message->delete_extension(TLSProxy::Message::EXT_EXTENDED_MASTER_SECRET);
            $message->repack();
        }
    }
}

sub checkmessages($$$$$)
{
    my ($testno, $testname, $testcextms, $testsextms, $testhand) = @_;

    subtest $testname => sub {

    foreach my $message (@{$proxy->message_list}) {
        if ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO
            || $message->mt == TLSProxy::Message::MT_SERVER_HELLO) {
        #Get the extensions data
        my %extensions = %{$message->extension_data};
        if (defined
            $extensions{TLSProxy::Message::EXT_EXTENDED_MASTER_SECRET}) {
            if ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO) {
                $cextms = 1;
            } else {
                $sextms = 1;
            }
        }
        } elsif ($message->mt == TLSProxy::Message::MT_CLIENT_KEY_EXCHANGE) {
            #Must be doing a full handshake
            $fullhand = 1;
        }
    }

    plan tests => 4;

    ok(TLSProxy::Message->success, "Handshake");

    ok($testcextms == $cextms,
       "ClientHello extension extended master secret check");
    ok($testsextms == $sextms,
       "ServerHello extension extended master secret check");
    ok($testhand == $fullhand,
       "Extended master secret full handshake check");

    }
}

sub setrmextms($$)
{
    ($crmextms, $srmextms) = @_;
}

sub clearall()
{
    $cextms = 0;
    $sextms = 0;
    $fullhand = 0;
    $proxy->clear();
}
