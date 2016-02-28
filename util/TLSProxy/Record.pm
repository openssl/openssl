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

package TLSProxy::Record;

my $server_ccs_seen = 0;
my $client_ccs_seen = 0;
my $etm = 0;

use constant TLS_RECORD_HEADER_LENGTH => 5;

#Record types
use constant {
    RT_APPLICATION_DATA => 23,
    RT_HANDSHAKE => 22,
    RT_ALERT => 21,
    RT_CCS => 20
};

my %record_type = (
    RT_APPLICATION_DATA, "APPLICATION DATA",
    RT_HANDSHAKE, "HANDSHAKE",
    RT_ALERT, "ALERT",
    RT_CCS, "CCS"
);

use constant {
    VERS_TLS_1_3 => 772,
    VERS_TLS_1_2 => 771,
    VERS_TLS_1_1 => 770,
    VERS_TLS_1_0 => 769,
    VERS_SSL_3_0 => 768,
    VERS_SSL_LT_3_0 => 767
};

my %tls_version = (
    VERS_TLS_1_3, "TLS1.3",
    VERS_TLS_1_2, "TLS1.2",
    VERS_TLS_1_1, "TLS1.1",
    VERS_TLS_1_0, "TLS1.0",
    VERS_SSL_3_0, "SSL3",
    VERS_SSL_LT_3_0, "SSL<3"
);

#Class method to extract records from a packet of data
sub get_records
{
    my $class = shift;
    my $server = shift;
    my $flight = shift;
    my $packet = shift;
    my @record_list = ();
    my @message_list = ();
    my $data;
    my $content_type;
    my $version;
    my $len;
    my $len_real;
    my $decrypt_len;

    my $recnum = 1;
    while (length ($packet) > 0) {
        print " Record $recnum";
        if ($server) {
            print " (server -> client)\n";
        } else {
            print " (client -> server)\n";
        }
        #Get the record header
        if (length($packet) < TLS_RECORD_HEADER_LENGTH) {
            print "Partial data : ".length($packet)." bytes\n";
            $packet = "";
        } else {
            ($content_type, $version, $len) = unpack('CnnC*', $packet);
            $data = substr($packet, 5, $len);

            print "  Content type: ".$record_type{$content_type}."\n";
            print "  Version: $tls_version{$version}\n";
            print "  Length: $len";
            if ($len == length($data)) {
                print "\n";
                $decrypt_len = $len_real = $len;
            } else {
                print " (expected), ".length($data)." (actual)\n";
                $decrypt_len = $len_real = length($data);
            }

            my $record = TLSProxy::Record->new(
                $flight,
                $content_type,
                $version,
                $len,
                $len_real,
                $decrypt_len,
                substr($packet, TLS_RECORD_HEADER_LENGTH, $len_real),
                substr($packet, TLS_RECORD_HEADER_LENGTH, $len_real)
            );

            if (($server && $server_ccs_seen)
                     || (!$server && $client_ccs_seen)) {
                if ($etm) {
                    $record->decryptETM();
                } else {
                    $record->decrypt();
                }
            }

            push @record_list, $record;

            #Now figure out what messages are contained within this record
            my @messages = TLSProxy::Message->get_messages($server, $record);
            push @message_list, @messages;

            $packet = substr($packet, TLS_RECORD_HEADER_LENGTH + $len_real);
            $recnum++;
        }
    }

    return (\@record_list, \@message_list);
}

sub clear
{
    $server_ccs_seen = 0;
    $client_ccs_seen = 0;
}

#Class level accessors
sub server_ccs_seen
{
    my $class = shift;
    if (@_) {
      $server_ccs_seen = shift;
    }
    return $server_ccs_seen;
}
sub client_ccs_seen
{
    my $class = shift;
    if (@_) {
      $client_ccs_seen = shift;
    }
    return $client_ccs_seen;
}
#Enable/Disable Encrypt-then-MAC
sub etm
{
    my $class = shift;
    if (@_) {
      $etm = shift;
    }
    return $etm;
}

sub new
{
    my $class = shift;
    my ($flight,
        $content_type,
        $version,
        $len,
        $len_real,
        $decrypt_len,
        $data,
        $decrypt_data) = @_;
    
    my $self = {
        flight => $flight,
        content_type => $content_type,
        version => $version,
        len => $len,
        len_real => $len_real,
        decrypt_len => $decrypt_len,
        data => $data,
        decrypt_data => $decrypt_data,
        orig_decrypt_data => $decrypt_data
    };

    return bless $self, $class;
}

#Decrypt using encrypt-then-MAC
sub decryptETM
{
    my ($self) = shift;

    my $data = $self->data;

    if($self->version >= VERS_TLS_1_1()) {
        #TLS1.1+ has an explicit IV. Throw it away
        $data = substr($data, 16);
    }

    #Throw away the MAC (assumes MAC is 20 bytes for now. FIXME)
    $data = substr($data, 0, length($data) - 20);

    #Find out what the padding byte is
    my $padval = unpack("C", substr($data, length($data) - 1));

    #Throw away the padding
    $data = substr($data, 0, length($data) - ($padval + 1));

    $self->decrypt_data($data);
    $self->decrypt_len(length($data));

    return $data;
}

#Standard decrypt
sub decrypt()
{
    my ($self) = shift;

    my $data = $self->data;

    if($self->version >= VERS_TLS_1_1()) {
        #TLS1.1+ has an explicit IV. Throw it away
        $data = substr($data, 16);
    }

    #Find out what the padding byte is
    my $padval = unpack("C", substr($data, length($data) - 1));

    #Throw away the padding
    $data = substr($data, 0, length($data) - ($padval + 1));

    #Throw away the MAC (assumes MAC is 20 bytes for now. FIXME)
    $data = substr($data, 0, length($data) - 20);

    $self->decrypt_data($data);
    $self->decrypt_len(length($data));

    return $data;
}

#Reconstruct the on-the-wire record representation
sub reconstruct_record
{
    my $self = shift;
    my $data;

    $data = pack('Cnn', $self->content_type, $self->version, $self->len);
    $data .= $self->data;

    return $data;
}

#Read only accessors
sub flight
{
    my $self = shift;
    return $self->{flight};
}
sub content_type
{
    my $self = shift;
    return $self->{content_type};
}
sub version
{
    my $self = shift;
    return $self->{version};
}
sub len_real
{
    my $self = shift;
    return $self->{len_real};
}
sub orig_decrypt_data
{
    my $self = shift;
    return $self->{orig_decrypt_data};
}

#Read/write accessors
sub decrypt_len
{
    my $self = shift;
    if (@_) {
      $self->{decrypt_len} = shift;
    }
    return $self->{decrypt_len};
}
sub data
{
    my $self = shift;
    if (@_) {
      $self->{data} = shift;
    }
    return $self->{data};
}
sub decrypt_data
{
    my $self = shift;
    if (@_) {
      $self->{decrypt_data} = shift;
    }
    return $self->{decrypt_data};
}
sub len
{
    my $self = shift;
    if (@_) {
      $self->{len} = shift;
    }
    return $self->{len};
}
1;
