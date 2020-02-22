#! /usr/bin/env perl
# Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT with bldtop_file srctop_file cmdstr/;
use OpenSSL::Test::Utils;

setup("test_verify_store");

plan tests => 10;

my $dummycnf = srctop_file("apps", "openssl.cnf");

my $CAkey = "keyCA.ss";
my $CAcert="certCA.ss";
my $CAserial="certCA.srl";
my $CAreq="reqCA.ss";
my $CAconf=srctop_file("test","CAss.cnf");
my $CAreq2="req2CA.ss";	# temp

my $Uconf=srctop_file("test","Uss.cnf");
my $Ukey="keyU.ss";
my $Ureq="reqU.ss";
my $Ucert="certU.ss";

SKIP: {
    req( 'make cert request',
         qw(-new),
         -config       => $CAconf,
         -out          => $CAreq,
         -keyout       => $CAkey );

    skip 'failure', 8 unless
        x509( 'convert request into self-signed cert',
              qw(-req -CAcreateserial),
              -in       => $CAreq,
              -out      => $CAcert,
              -signkey  => $CAkey,
              -days     => 30,
              -extfile  => $CAconf,
              -extensions => 'v3_ca' );

    skip 'failure', 7 unless
        x509( 'convert cert into a cert request',
              qw(-x509toreq),
              -in       => $CAcert,
              -out      => $CAreq2,
              -signkey  => $CAkey );

    skip 'failure', 6 unless
        req( 'verify request 1',
             qw(-verify -noout),
             -config    => $dummycnf,
             -in        => $CAreq );

    skip 'failure', 5 unless
        req( 'verify request 2',
             qw(-verify -noout),
             -config    => $dummycnf,
             -in        => $CAreq2 );

    skip 'failure', 4 unless
        verify( 'verify signature',
                -CAstore => $CAcert,
                $CAcert );

    skip 'failure', 3 unless
        req( 'make a user cert request',
             qw(-new),
             -config  => $Uconf,
             -out     => $Ureq,
             -keyout  => $Ukey );

    skip 'failure', 2 unless
        x509( 'sign user cert request',
              qw(-req -CAcreateserial),
              -in     => $Ureq,
              -out    => $Ucert,
              -CA     => $CAcert,
              -CAkey  => $CAkey,
              -CAserial => $CAserial,
              -days   => 30,
              -extfile => $Uconf,
              -extensions => 'v3_ee' )
        && verify( undef,
                   -CAstore => $CAcert,
                   $Ucert );

    skip 'failure', 0 unless
        x509( 'Certificate details',
              qw( -subject -issuer -startdate -enddate -noout),
              -in     => $Ucert );
}

sub verify {
    my $title = shift;

    ok(run(app([qw(openssl verify), @_])), $title);
}

sub req {
    my $title = shift;

    ok(run(app([qw(openssl req), @_])), $title);
}

sub x509 {
    my $title = shift;

    ok(run(app([qw(openssl x509), @_])), $title);
}
