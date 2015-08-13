#!/usr/bin/perl
# Written by Matt Caswell for the OpenSSL project.
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
use TLSProxy::Proxy;
use File::Temp qw(tempfile);

my $chellotickext = 0;
my $shellotickext = 0;
my $fullhand = 0;
my $ticketseen = 0;

my $proxy = TLSProxy::Proxy->new(
    undef,
    @ARGV
);

#Test 1: By default with no existing session we should get a session ticket
#Expected result: ClientHello extension seen; ServerHello extension seen
#                 NewSessionTicket message seen; Full handshake
$proxy->start();
checkmessages(1, "Default session ticket test", 1, 1, 1, 1);

#Test 2: If the server does not accept tickets we should get a normal handshake
#with no session tickets
#Expected result: ClientHello extension seen; ServerHello extension not seen
#                 NewSessionTicket message not seen; Full handshake
clearall();
$proxy->serverflags("-no_ticket");
$proxy->start();
checkmessages(2, "No server support session ticket test", 1, 0, 0, 1);

#Test 3: If the client does not accept tickets we should get a normal handshake
#with no session tickets
#Expected result: ClientHello extension not seen; ServerHello extension not seen
#                 NewSessionTicket message not seen; Full handshake
clearall();
$proxy->clientflags("-no_ticket");
$proxy->start();
checkmessages(3, "No client support session ticket test", 0, 0, 0, 1);

#Test 4: Test session resumption with session ticket
#Expected result: ClientHello extension seen; ServerHello extension not seen
#                 NewSessionTicket message not seen; Abbreviated handshake
clearall();
(my $fh, my $session) = tempfile();
$proxy->serverconnects(2);
$proxy->clientflags("-sess_out ".$session);
$proxy->start();
$proxy->clear();
$proxy->clientflags("-sess_in ".$session);
$proxy->clientstart();
checkmessages(4, "Session resumption session ticket test", 1, 0, 0, 0);

#Test 5: Test session resumption with ticket capable client without a ticket
#Expected result: ClientHello extension seen; ServerHello extension seen
#                 NewSessionTicket message seen; Abbreviated handshake
clearall();
(my $fh, my $session) = tempfile();
$proxy->serverconnects(2);
$proxy->clientflags("-sess_out ".$session." -no_ticket");
$proxy->start();
$proxy->clear();
$proxy->clientflags("-sess_in ".$session);
$proxy->clientstart();
checkmessages(5, "Session resumption with ticket capable client without a "
                 ."ticket", 1, 1, 1, 0);

sub checkmessages()
{
    my ($testno, $testname, $testch, $testsh, $testtickseen, $testhand) = @_;

    foreach my $message (@{$proxy->message_list}) {
        if ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO
                || $message->mt == TLSProxy::Message::MT_SERVER_HELLO) {
            #Get the extensions data
            my %extensions = %{$message->extension_data};
            if (defined
                    $extensions{TLSProxy::ClientHello::EXT_SESSION_TICKET}) {
                if ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO) {
                    $chellotickext = 1;
                } else {
                    $shellotickext = 1;
                }
            }
        } elsif ($message->mt == TLSProxy::Message::MT_CLIENT_KEY_EXCHANGE) {
            #Must be doing a full handshake
            $fullhand = 1;
        } elsif ($message->mt == TLSProxy::Message::MT_NEW_SESSION_TICKET) {
            $ticketseen = 1;
        }
    }

    TLSProxy::Message->success or die "FAILED: $testname: Hanshake failed "
                                      ."(Test $testno)\n";
    if (($testch && !$chellotickext) || (!$testch && $chellotickext)) {
        die "FAILED: $testname: ClientHello extension Session Ticket check "
            ."failed (Test $testno)\n";
    }
    if (($testsh && !$shellotickext) || (!$testsh && $shellotickext)) {
        die "FAILED: $testname: ServerHello extension Session Ticket check "
            ."failed (Test $testno)\n";
    }
    if (($testtickseen && !$ticketseen) || (!$testtickseen && $ticketseen)) {
        die "FAILED: $testname: Session Ticket message presence check failed "
            ."(Test $testno)\n";
    }
    if (($testhand && !$fullhand) || (!$testhand && $fullhand)) {
        die "FAILED: $testname: Session Ticket full handshake check failed "
            ."(Test $testno)\n";
    }
    print "SUCCESS: $testname (Test#$testno)\n";
}

sub clearall()
{
    $chellotickext = 0;
    $shellotickext = 0;
    $fullhand = 0;
    $ticketseen = 0;
    $proxy->clear();
}
