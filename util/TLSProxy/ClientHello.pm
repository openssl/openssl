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

package TLSProxy::ClientHello;

use parent 'TLSProxy::Message';

use constant {
    EXT_ENCRYPT_THEN_MAC => 22,
    EXT_SESSION_TICKET => 35
};

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
        1,
        $data,
        $records,
        $startoffset,
        $message_frag_lens);

    $self->{client_version} = 0;
    $self->{random} = [];
    $self->{session_id_len} = 0;
    $self->{session} = "";
    $self->{ciphersuite_len} = 0;
    $self->{ciphersuites} = [];
    $self->{comp_meth_len} = 0;
    $self->{comp_meths} = [];
    $self->{extensions_len} = 0;
    $self->{extensions_data} = "";

    return $self;
}

sub parse
{
    my $self = shift;
    my $ptr = 2;
    my ($client_version) = unpack('n', $self->data);
    my $random = substr($self->data, $ptr, 32);
    $ptr += 32;
    my $session_id_len = unpack('C', substr($self->data, $ptr));
    $ptr++;
    my $session = substr($self->data, $ptr, $session_id_len);
    $ptr += $session_id_len;
    my $ciphersuite_len = unpack('n', substr($self->data, $ptr));
    $ptr += 2;
    my @ciphersuites = unpack('n*', substr($self->data, $ptr,
                                           $ciphersuite_len));
    $ptr += $ciphersuite_len;
    my $comp_meth_len = unpack('C', substr($self->data, $ptr));
    $ptr++;
    my @comp_meths = unpack('C*', substr($self->data, $ptr, $comp_meth_len));
    $ptr += $comp_meth_len;
    my $extensions_len = unpack('n', substr($self->data, $ptr));
    $ptr += 2;
    #For now we just deal with this as a block of data. In the future we will
    #want to parse this
    my $extension_data = substr($self->data, $ptr);
    
    if (length($extension_data) != $extensions_len) {
        die "Invalid extension length\n";
    }
    my %extensions = ();
    while (length($extension_data) >= 4) {
        my ($type, $size) = unpack("nn", $extension_data);
        my $extdata = substr($extension_data, 4, $size);
        $extension_data = substr($extension_data, 4 + $size);
        $extensions{$type} = $extdata;
    }

    $self->client_version($client_version);
    $self->random($random);
    $self->session_id_len($session_id_len);
    $self->session($session);
    $self->ciphersuite_len($ciphersuite_len);
    $self->ciphersuites(\@ciphersuites);
    $self->comp_meth_len($comp_meth_len);
    $self->comp_meths(\@comp_meths);
    $self->extensions_len($extensions_len);
    $self->extension_data(\%extensions);

    $self->process_extensions();

    print "    Client Version:".$client_version."\n";
    print "    Session ID Len:".$session_id_len."\n";
    print "    Ciphersuite len:".$ciphersuite_len."\n";
    print "    Compression Method Len:".$comp_meth_len."\n";
    print "    Extensions Len:".$extensions_len."\n";
}

#Perform any actions necessary based on the extensions we've seen
sub process_extensions
{
    my $self = shift;
    my %extensions = %{$self->extension_data};

    #Clear any state from a previous run
    TLSProxy::Record->etm(0);

    if (exists $extensions{&EXT_ENCRYPT_THEN_MAC}) {
        TLSProxy::Record->etm(1);
    }
}

#Reconstruct the on-the-wire message data following changes
sub set_message_contents
{
    my $self = shift;
    my $data;

    $data = pack('n', $self->client_version);
    $data .= $self->random;
    $data .= pack('C', $self->session_id_len);
    $data .= $self->session;
    $data .= pack('n', $self->ciphersuite_len);
    $data .= pack("n*", @{$self->ciphersuites});
    $data .= pack('C', $self->comp_meth_len);
    $data .= pack("C*", @{$self->comp_meths});
    $data .= pack('n', $self->extensions_len);
    foreach my $key (keys %{$self->extension_data}) {
        my $extdata = ${$self->extension_data}{$key};
        $data .= pack("n", $key);
        $data .= pack("n", length($extdata));
        $data .= $extdata;
    }

    $self->data($data);
}

#Read/write accessors
sub client_version
{
    my $self = shift;
    if (@_) {
      $self->{client_version} = shift;
    }
    return $self->{client_version};
}
sub random
{
    my $self = shift;
    if (@_) {
      $self->{random} = shift;
    }
    return $self->{random};
}
sub session_id_len
{
    my $self = shift;
    if (@_) {
      $self->{session_id_len} = shift;
    }
    return $self->{session_id_len};
}
sub session
{
    my $self = shift;
    if (@_) {
      $self->{session} = shift;
    }
    return $self->{session};
}
sub ciphersuite_len
{
    my $self = shift;
    if (@_) {
      $self->{ciphersuite_len} = shift;
    }
    return $self->{ciphersuite_len};
}
sub ciphersuites
{
    my $self = shift;
    if (@_) {
      $self->{ciphersuites} = shift;
    }
    return $self->{ciphersuites};
}
sub comp_meth_len
{
    my $self = shift;
    if (@_) {
      $self->{comp_meth_len} = shift;
    }
    return $self->{comp_meth_len};
}
sub comp_meths
{
    my $self = shift;
    if (@_) {
      $self->{comp_meths} = shift;
    }
    return $self->{comp_meths};
}
sub extensions_len
{
    my $self = shift;
    if (@_) {
      $self->{extensions_len} = shift;
    }
    return $self->{extensions_len};
}
sub extension_data
{
    my $self = shift;
    if (@_) {
      $self->{extension_data} = shift;
    }
    return $self->{extension_data};
}
1;
