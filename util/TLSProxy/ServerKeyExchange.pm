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

package TLSProxy::ServerKeyExchange;

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
        TLSProxy::Message::MT_SERVER_KEY_EXCHANGE,
        $data,
        $records,
        $startoffset,
        $message_frag_lens);

    #DHE
    $self->{p} = "";
    $self->{g} = "";
    $self->{pub_key} = "";
    $self->{sig} = "";

    return $self;
}

sub parse
{
    my $self = shift;

    #Minimal SKE parsing. Only supports DHE at the moment (if its not DHE
    #the parsing data will be trash...which is ok as long as we don't try to
    #use it)

    my $p_len = unpack('n', $self->data);
    my $ptr = 2;
    my $p = substr($self->data, $ptr, $p_len);
    $ptr += $p_len;

    my $g_len = unpack('n', substr($self->data, $ptr));
    $ptr += 2;
    my $g = substr($self->data, $ptr, $g_len);
    $ptr += $g_len;

    my $pub_key_len = unpack('n', substr($self->data, $ptr));
    $ptr += 2;
    my $pub_key = substr($self->data, $ptr, $pub_key_len);
    $ptr += $pub_key_len;

    #We assume its signed
    my $sig_len = unpack('n', substr($self->data, $ptr));
    my $sig = "";
    if (defined $sig_len) {
	$ptr += 2;
	$sig = substr($self->data, $ptr, $sig_len);
	$ptr += $sig_len;
    }

    $self->p($p);
    $self->g($g);
    $self->pub_key($pub_key);
    $self->sig($sig);
}


#Reconstruct the on-the-wire message data following changes
sub set_message_contents
{
    my $self = shift;
    my $data;

    $data = pack('n', length($self->p));
    $data .= $self->p;
    $data .= pack('n', length($self->g));
    $data .= $self->g;
    $data .= pack('n', length($self->pub_key));
    $data .= $self->pub_key;
    if (length($self->sig) > 0) {
        $data .= pack('n', length($self->sig));
        $data .= $self->sig;
    }

    $self->data($data);
}

#Read/write accessors
#DHE
sub p
{
    my $self = shift;
    if (@_) {
      $self->{p} = shift;
    }
    return $self->{p};
}
sub g
{
    my $self = shift;
    if (@_) {
      $self->{g} = shift;
    }
    return $self->{g};
}
sub pub_key
{
    my $self = shift;
    if (@_) {
      $self->{pub_key} = shift;
    }
    return $self->{pub_key};
}
sub sig
{
    my $self = shift;
    if (@_) {
      $self->{sig} = shift;
    }
    return $self->{sig};
}
1;
