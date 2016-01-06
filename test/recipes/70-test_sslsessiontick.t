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
use OpenSSL::Test qw/:DEFAULT cmdstr top_file top_dir/;
use TLSProxy::Proxy;
use File::Temp qw(tempfile);

my $test_name = "test_sslsessiontick";
setup($test_name);

plan skip_all => "$test_name can only be performed with OpenSSL configured shared"
    unless (map { s/\R//; s/^SHARED_LIBS=\s*//; $_ }
	    grep { /^SHARED_LIBS=/ }
	    do { local @ARGV = ( top_file("Makefile") ); <> })[0] ne "";

$ENV{OPENSSL_ENGINES} = top_dir("engines");
$ENV{OPENSSL_ia32cap} = '~0x200000200000000';

sub checkmessages($$$$$$);
sub clearall();

my $chellotickext = 0;
my $shellotickext = 0;
my $fullhand = 0;
my $ticketseen = 0;

my $proxy = TLSProxy::Proxy->new(
    undef,
    cmdstr(app(["openssl"])),
    top_file("apps", "server.pem")
);

plan tests => 8;

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
($fh, $session) = tempfile();
$proxy->serverconnects(2);
$proxy->clientflags("-sess_out ".$session." -no_ticket");
$proxy->start();
$proxy->clear();
$proxy->clientflags("-sess_in ".$session);
$proxy->clientstart();
checkmessages(5, "Session resumption with ticket capable client without a "
                 ."ticket", 1, 1, 1, 0);

#Test 6: Client accepts empty ticket.
#Expected result: ClientHello extension seen; ServerHello extension seen;
#                 NewSessionTicket message seen; Full handshake.
clearall();
$proxy->filter(\&ticket_filter);
$proxy->start();
checkmessages(6, "Empty ticket test",  1, 1, 1, 1);

#Test 7-8: Client keeps existing ticket on empty ticket.
clearall();
($fh, $session) = tempfile();
$proxy->serverconnects(3);
$proxy->filter(undef);
$proxy->clientflags("-sess_out ".$session);
$proxy->start();
$proxy->clear();
$proxy->clientflags("-sess_in ".$session." -sess_out ".$session);
$proxy->filter(\&inject_empty_ticket_filter);
$proxy->clientstart();
#Expected result: ClientHello extension seen; ServerHello extension seen;
#                 NewSessionTicket message seen; Abbreviated handshake.
checkmessages(7, "Empty ticket resumption test",  1, 1, 1, 0);
clearall();
$proxy->clientflags("-sess_in ".$session);
$proxy->filter(undef);
$proxy->clientstart();
#Expected result: ClientHello extension seen; ServerHello extension not seen;
#                 NewSessionTicket message not seen; Abbreviated handshake.
checkmessages(8, "Empty ticket resumption test",  1, 0, 0, 0);


sub ticket_filter
{
    my $proxy = shift;

    foreach my $message (@{$proxy->message_list}) {
        if ($message->mt == TLSProxy::Message::MT_NEW_SESSION_TICKET) {
            $message->ticket("");
            $message->repack();
        }
    }
}

sub inject_empty_ticket_filter {
    my $proxy = shift;

    foreach my $message (@{$proxy->message_list}) {
        if ($message->mt == TLSProxy::Message::MT_NEW_SESSION_TICKET) {
            # Only inject the message first time we're called.
            return;
        }
    }

    my @new_message_list = ();
    foreach my $message (@{$proxy->message_list}) {
        push @new_message_list, $message;
        if ($message->mt == TLSProxy::Message::MT_SERVER_HELLO) {
            $message->set_extension(TLSProxy::ClientHello::EXT_SESSION_TICKET, "");
            $message->repack();
            # Tack NewSessionTicket onto the ServerHello record.
            # This only works if the ServerHello is exactly one record.
            my $record = ${$message->records}[0];

            my $offset = $message->startoffset + $message->encoded_length;
            my $newsessionticket = TLSProxy::NewSessionTicket->new(
                1, "", [$record], $offset, []);
            $newsessionticket->repack();
            push @new_message_list, $newsessionticket;
        }
    }
    $proxy->message_list([@new_message_list]);
}

sub checkmessages($$$$$$)
{
    my ($testno, $testname, $testch, $testsh, $testtickseen, $testhand) = @_;

    subtest $testname => sub {

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

	plan tests => 5;

	ok(TLSProxy::Message->success, "Handshake");
	ok(($testch && $chellotickext) || (!$testch && !$chellotickext),
	   "ClientHello extension Session Ticket check");
	ok(($testsh && $shellotickext) || (!$testsh && !$shellotickext),
	   "ServerHello extension Session Ticket check");
	ok(($testtickseen && $ticketseen) || (!$testtickseen && !$ticketseen),
	   "Session Ticket message presence check");
	ok(($testhand && $fullhand) || (!$testhand && !$fullhand),
	   "Session Ticket full handshake check");
    }
}

sub clearall()
{
    $chellotickext = 0;
    $shellotickext = 0;
    $fullhand = 0;
    $ticketseen = 0;
    $proxy->clear();
}
