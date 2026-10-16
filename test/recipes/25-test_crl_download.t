#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use IO::Socket::INET;
use POSIX ();
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_crl_download");

plan skip_all => "sockets or HTTP support are disabled in this build"
    if disabled("sock") || disabled("http");
plan skip_all => "test not supported on this platform"
    if $^O =~ /^(VMS|MSWin32|msys)$/;

# A minimal HTTP server on 127.0.0.1: it logs the request line of every
# request it receives to $reqlog and answers 404, so no CRL is ever obtained.
my $listener = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                     Proto => 'tcp', Listen => 5,
                                     ReuseAddr => 1)
    or plan skip_all => "cannot listen on 127.0.0.1: $!";
my $port = $listener->sockport();
my $reqlog = "crl_download_requests.txt";

my $pid = fork();
plan skip_all => "fork failed: $!" unless defined $pid;
if ($pid == 0) {
    while (my $conn = $listener->accept()) {
        my $request = <$conn>;

        if (defined $request && open(my $log, '>>', $reqlog)) {
            print $log $request;
            close $log;
        }
        print $conn "HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        close $conn;
    }
    POSIX::_exit(0);
}
close $listener;

plan tests => 6;

my $root = srctop_file('test', 'certs', 'root-cert.pem');
my $ca = srctop_file('test', 'certs', 'ca-cert.pem');
my $cakey = srctop_file('test', 'certs', 'ca-key.pem');
my $eekey = srctop_file('test', 'certs', 'ee-key.pem');
my $url = "http://127.0.0.1:$port/good.crl";

# Write a configuration file with a CRL distribution point whose URI is
# $uri, given as raw bytes; the ASN.1 generation syntax with a hex encoded
# [6] IMPLICIT string allows an embedded NUL byte in the IA5String.
sub crldp_config {
    my ($file, $uri) = @_;
    my $hex = unpack("H*", $uri);

    open(my $cnf, '>', $file) or die "cannot write $file: $!";
    print $cnf <<"EOF";
[ v3 ]
crlDistributionPoints = ASN1:SEQUENCE:dps
[ dps ]
dp = SEQUENCE:dp
[ dp ]
distributionPoint = EXP:0,IMP:0,SEQUENCE:names
[ names ]
uri = IMP:6,FORMAT:HEX,OCTETSTRING:$hex
EOF
    close $cnf;
}

sub make_cert {
    my ($name, $uri, $serial) = @_;

    crldp_config("$name.cnf", $uri);
    return run(app(['openssl', 'req', '-new', '-key', $eekey,
                    '-subj', '/CN=CRL download test',
                    '-out', "$name.csr"]))
        && run(app(['openssl', 'x509', '-req', '-in', "$name.csr",
                    '-CA', $ca, '-CAkey', $cakey, '-set_serial', $serial,
                    '-days', '3650', '-extfile', "$name.cnf",
                    '-extensions', 'v3', '-out', "$name.pem"]));
}

sub verify_with_crl_download {
    my $cert = shift;

    unlink $reqlog;
    return run(app(['openssl', 'verify', '-CAfile', $root,
                    '-untrusted', $ca, '-crl_check', '-crl_download',
                    $cert]));
}

sub requests {
    open(my $log, '<', $reqlog) or return "";
    local $/;
    my $requests = <$log>;
    close $log;
    return $requests;
}

# Control: the CRL is requested from the URI found in the certificate.
ok(make_cert("crldp-plain", $url, 1),
   "create a certificate with an http CRL distribution point");
ok(!verify_with_crl_download("crldp-plain.pem"),
   "verification fails when the CRL cannot be downloaded");
like(requests(), qr{^GET /good\.crl },
     "the CRL was requested from the URI in the certificate");

# A URI with an embedded NUL byte must not be fetched at all: before it
# was checked the URI was truncated at the NUL and the resulting URL was
# fetched instead.
ok(make_cert("crldp-nul", "$url\0/evil", 2),
   "create a certificate with an embedded NUL in the CRL distribution point");
ok(!verify_with_crl_download("crldp-nul.pem"),
   "verification fails with an embedded NUL in the CRL distribution point");
is(requests(), "", "no CRL was requested from the truncated URI");

kill('KILL', $pid);
waitpid($pid, 0);
