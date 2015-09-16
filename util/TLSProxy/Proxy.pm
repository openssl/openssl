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

package TLSProxy::Proxy;

use File::Spec;
use IO::Socket;
use IO::Select;
use TLSProxy::Record;
use TLSProxy::Message;
use TLSProxy::ClientHello;
use TLSProxy::ServerHello;
use TLSProxy::ServerKeyExchange;
use TLSProxy::NewSessionTicket;

sub new
{
    my $class = shift;
    my ($filter,
        $execute,
        $cert,
        $debug) = @_;

    my $self = {
        #Public read/write
        proxy_addr => "localhost",
        proxy_port => 4453,
        server_addr => "localhost",
        server_port => 4443,
        filter => $filter,
        serverflags => "",
        clientflags => "",
        serverconnects => 1,

        #Public read
        execute => $execute,
        cert => $cert,
        debug => $debug,
        cipherc => "",
        ciphers => "AES128-SHA",
        flight => 0,
        record_list => [],
        message_list => [],
    };

    return bless $self, $class;
}

sub clear
{
    my $self = shift;

    $self->{cipherc} = "";
    $self->{ciphers} = "AES128-SHA";
    $self->{flight} = 0;
    $self->{record_list} = [];
    $self->{message_list} = [];
    $self->{serverflags} = "";
    $self->{clientflags} = "";
    $self->{serverconnects} = 1;

    TLSProxy::Message->clear();
    TLSProxy::Record->clear();
}

sub restart
{
    my $self = shift;

    $self->clear;
    $self->start;
}

sub clientrestart
{
    my $self = shift;

    $self->clear;
    $self->clientstart;
}

sub start
{
    my ($self) = shift;
    my $pid;

    $pid = fork();
    if ($pid == 0) {
        open(STDOUT, ">", File::Spec->devnull())
            or die "Failed to redirect stdout";
        open(STDERR, ">&STDOUT");
        my $execcmd = $self->execute
            ." s_server -no_comp -rev -engine ossltest -accept "
            .($self->server_port)
            ." -cert ".$self->cert." -naccept ".$self->serverconnects;
        if ($self->ciphers ne "") {
            $execcmd .= " -cipher ".$self->ciphers;
        }
        if ($self->serverflags ne "") {
            $execcmd .= " ".$self->serverflags;
        }
        exec($execcmd);
    }

    $self->clientstart;
}

sub clientstart
{
    my ($self) = shift;
    my $oldstdout;

    if(!$self->debug) {
        open DEVNULL, ">", File::Spec->devnull();
        $oldstdout = select(DEVNULL);
    }

    # Create the Proxy socket
    my $proxy_sock = new IO::Socket::INET(
        LocalHost   => $self->proxy_addr,
        LocalPort   => $self->proxy_port,
        Proto       => "tcp",
        Listen      => SOMAXCONN,
        Reuse       => 1
    );

    if ($proxy_sock) {
        print "Proxy started on port ".$self->proxy_port."\n";
    } else {
        die "Failed creating proxy socket\n";
    }

    if ($self->execute) {
        my $pid = fork();
        if ($pid == 0) {
            open(STDOUT, ">", File::Spec->devnull())
                or die "Failed to redirect stdout";
            open(STDERR, ">&STDOUT");
            my $execcmd = "echo test | ".$self->execute
                 ." s_client -engine ossltest -connect "
                 .($self->proxy_addr).":".($self->proxy_port);
            if ($self->cipherc ne "") {
                $execcmd .= " -cipher ".$self->cipherc;
            }
            if ($self->clientflags ne "") {
                $execcmd .= " ".$self->clientflags;
            }
            exec($execcmd);
        }
    }

    # Wait for incoming connection from client
    my $client_sock = $proxy_sock->accept() 
        or die "Failed accepting incoming connection\n";

    print "Connection opened\n";

    # Now connect to the server
    my $retry = 3;
    my $server_sock;
    #We loop over this a few times because sometimes s_server can take a while
    #to start up
    do {
        $server_sock = new IO::Socket::INET(
            PeerAddr => $self->server_addr,
            PeerPort => $self->server_port,
            Proto => 'tcp'
        ); 

        $retry--;
        if (!$server_sock) {
            if ($retry) {
                #Sleep for a short while
                select(undef, undef, undef, 0.1);
            } else {
                die "Failed to start up server\n";
            }
        }
    } while (!$server_sock);

    my $sel = IO::Select->new($server_sock, $client_sock);
    my $indata;
    my @handles = ($server_sock, $client_sock);

    #Wait for either the server socket or the client socket to become readable
    my @ready;
    while(!(TLSProxy::Message->end) && (@ready = $sel->can_read)) {
        foreach my $hand (@ready) {
            if ($hand == $server_sock) {
                $server_sock->sysread($indata, 16384) or goto END;
                $indata = $self->process_packet(1, $indata);
                $client_sock->syswrite($indata);
            } elsif ($hand == $client_sock) {
                $client_sock->sysread($indata, 16384) or goto END;
                $indata = $self->process_packet(0, $indata);
                $server_sock->syswrite($indata);
            } else {
                print "Err\n";
                goto END;
            }
        }
    }

    END:
    print "Connection closed\n";
    if($server_sock) {
        $server_sock->close();
    }
    if($client_sock) {
        #Closing this also kills the child process
        $client_sock->close();
    }
    if($proxy_sock) {
        $proxy_sock->close();
    }
    if(!$self->debug) {
        select($oldstdout);
    }
}

sub process_packet
{
    my ($self, $server, $packet) = @_;
    my $len_real;
    my $decrypt_len;
    my $data;
    my $recnum;

    if ($server) {
        print "Received server packet\n";
    } else {
        print "Received client packet\n";
    }

    print "Packet length = ".length($packet)."\n";
    print "Processing flight ".$self->flight."\n";

    #Return contains the list of record found in the packet followed by the
    #list of messages in those records
    my @ret = TLSProxy::Record->get_records($server, $self->flight, $packet);
    push @{$self->record_list}, @{$ret[0]};
    push @{$self->{message_list}}, @{$ret[1]};

    print "\n";

    #Finished parsing. Call user provided filter here
    if(defined $self->filter) {
        $self->filter->($self);
    }

    #Reconstruct the packet
    $packet = "";
    foreach my $record (@{$self->record_list}) {
        #We only replay the records for the current flight
        if ($record->flight != $self->flight) {
            next;
        }
        $packet .= $record->reconstruct_record();
    }

    $self->{flight} = $self->{flight} + 1;

    print "Forwarded packet length = ".length($packet)."\n\n";

    return $packet;
}

#Read accessors
sub execute
{
    my $self = shift;
    return $self->{execute};
}
sub cert
{
    my $self = shift;
    return $self->{cert};
}
sub debug
{
    my $self = shift;
    return $self->{debug};
}
sub flight
{
    my $self = shift;
    return $self->{flight};
}
sub record_list
{
    my $self = shift;
    return $self->{record_list};
}
sub success
{
    my $self = shift;
    return $self->{success};
}
sub end
{
    my $self = shift;
    return $self->{end};
}

#Read/write accessors
sub proxy_addr
{
    my $self = shift;
    if (@_) {
      $self->{proxy_addr} = shift;
    }
    return $self->{proxy_addr};
}
sub proxy_port
{
    my $self = shift;
    if (@_) {
      $self->{proxy_port} = shift;
    }
    return $self->{proxy_port};
}
sub server_addr
{
    my $self = shift;
    if (@_) {
      $self->{server_addr} = shift;
    }
    return $self->{server_addr};
}
sub server_port
{
    my $self = shift;
    if (@_) {
      $self->{server_port} = shift;
    }
    return $self->{server_port};
}
sub filter
{
    my $self = shift;
    if (@_) {
      $self->{filter} = shift;
    }
    return $self->{filter};
}
sub cipherc
{
    my $self = shift;
    if (@_) {
      $self->{cipherc} = shift;
    }
    return $self->{cipherc};
}
sub ciphers
{
    my $self = shift;
    if (@_) {
      $self->{ciphers} = shift;
    }
    return $self->{ciphers};
}
sub serverflags
{
    my $self = shift;
    if (@_) {
      $self->{serverflags} = shift;
    }
    return $self->{serverflags};
}
sub clientflags
{
    my $self = shift;
    if (@_) {
      $self->{clientflags} = shift;
    }
    return $self->{clientflags};
}
sub serverconnects
{
    my $self = shift;
    if (@_) {
      $self->{serverconnects} = shift;
    }
    return $self->{serverconnects};
}
# This is a bit ugly because the caller is responsible for keeping the records
# in sync with the updated message list; simply updating the message list isn't
# sufficient to get the proxy to forward the new message.
# But it does the trick for the one test (test_sslsessiontick) that needs it.
sub message_list
{
    my $self = shift;
    if (@_) {
        $self->{message_list} = shift;
    }
    return $self->{message_list};
}
1;
