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

package TLSProxy::NewSessionTicket;

use parent 'TLSProxy::Message';

sub new
{
    my $class = shift;
    my ($server,
        $data,
        $records,
        $startoffset,
        $message_frag_lens) = @_;

    my $self = $class->SUPER::new(
        $server,
        TLSProxy::Message::MT_NEW_SESSION_TICKET,
        $data,
        $records,
        $startoffset,
        $message_frag_lens);

    $self->{ticket_lifetime_hint} = 0;
    $self->{ticket} = "";

    return $self;
}

sub parse
{
    my $self = shift;

    my $ticket_lifetime_hint = unpack('N', $self->data);
    my $ticket_len = unpack('n', $self->data);
    my $ticket = substr($self->data, 6, $ticket_len);

    $self->ticket_lifetime_hint($ticket_lifetime_hint);
    $self->ticket($ticket);
}


#Reconstruct the on-the-wire message data following changes
sub set_message_contents
{
    my $self = shift;
    my $data;

    $data = pack('N', $self->ticket_lifetime_hint);
    $data .= pack('n', length($self->ticket));
    $data .= $self->ticket;

    $self->data($data);
}

#Read/write accessors
sub ticket_lifetime_hint
{
    my $self = shift;
    if (@_) {
      $self->{ticket_lifetime_hint} = shift;
    }
    return $self->{ticket_lifetime_hint};
}
sub ticket
{
    my $self = shift;
    if (@_) {
      $self->{ticket} = shift;
    }
    return $self->{ticket};
}
1;
