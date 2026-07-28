#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# End-to-end test of Merkle Tree Certificate client authentication.  The server
# asks for a client certificate and, trusting the MTC CA (-mtc_cas), names that
# CA's trust anchor in the CertificateRequest; the client holds a credential for
# it (-tai_chains) and sends that rather than its ordinary certificate.  The
# fixtures are issued for server authentication, so the server validates with
# -purpose any.

use strict;
use warnings;

use IPC::Open3;
use OpenSSL::Test qw/:DEFAULT srctop_file bldtop_file/;
use OpenSSL::Test::Utils;

my $test_name = "test_mtc_client_auth";
setup($test_name);

plan skip_all => "$test_name requires sock enabled" if disabled("sock");
plan skip_all => "$test_name requires TLSv1.3 enabled" if disabled("tls1_3");
plan skip_all => "$test_name requires ML-DSA enabled" if disabled("ml-dsa");
plan skip_all => "$test_name is not available on Windows or VMS"
    if $^O =~ /^(VMS|MSWin32|msys)$/;

plan tests => 7;

my $shlib_wrap   = bldtop_file("util", "shlib_wrap.sh");
my $apps_openssl = bldtop_file("apps", "openssl");

# The server's own certificate, and the MTC CA it trusts for client
# certificates.
my $srvcert = srctop_file("test", "certs", "servercert.pem");
my $srvkey  = srctop_file("test", "certs", "serverkey.pem");
my $mtc_ca  = srctop_file("test", "mtc", "mtc-ca-cert.pem");

# The root the server's own certificate chains to, so that the client's
# verification succeeds and the only failure a run reports is a real one.
my $rootcert = srctop_file("test", "certs", "rootcert.pem");

# The standalone (cosigned) MTC credential the client sends, and its key.
my $mtc_cred = srctop_file("test", "mtc", "mtc-server.pem");
my $mtc_key  = srctop_file("test", "mtc", "mtc-server-key.pem");

sub slurp {
    my ($file) = @_;
    open(my $fh, "<", $file) or die "cannot read $file: $!";
    local $/;
    my $text = <$fh>;
    close($fh);
    return $text;
}

# The base64 body of the one certificate in a file, or of the certificate the
# peer sent, so that the two can be compared.  A properties block does not
# match: its line reads "BEGIN CERTIFICATE PROPERTIES".
sub cert_body {
    my ($text) = @_;
    my $body;

    return "" if $text !~
        /-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s;
    $body = $1;
    $body =~ s/\s+//g;
    return $body;
}

# The credential and its key in one file, so no separate -tai_keys is needed.
my $chains = "client-cred.pem";
open(my $out, ">", $chains) or die "cannot write $chains: $!";
print $out slurp($mtc_cred) . slurp($mtc_key);
close($out);

# Run one connection and return the accepted port, the client's output and the
# server's.  The server asks for a client certificate and requires one; with
# @client_extra empty the client has nothing to send.
sub run_case {
    my (@client_extra) = @_;
    my $port = "0";
    my ($cout, $sout) = ("", "");

    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm 60;

        # -attime pins verification to a fixed instant inside the fixtures'
        # validity (2020..2030), so the test does not expire when they do.
        my $spid = open3(my $si, my $so, my $se, $shlib_wrap, $apps_openssl,
            "s_server", "-accept", "0", "-naccept", "1",
            "-cert", $srvcert, "-key", $srvkey,
            "-mtc_cas", $mtc_ca, "-Verify", "1",
            "-purpose", "any", "-attime", "1735689600",
            "-no-CAfile", "-no-CApath", "-no-CAstore", "-tls1_3");
        while (<$so>) {
            if (/^ACCEPT 0.0.0.0:(\d+)/ || /^ACCEPT \[::\]:(\d+)/) {
                $port = $1;
                last;
            }
        }

        # -tlsextdebug so the extensions the server sent are in the output.
        my @ccmd = ("s_client", "-connect", "localhost:$port",
            "-CAfile", $rootcert, "-tlsextdebug",
            "-tls1_3", "-nameopt", "RFC2253", @client_extra);
        local (*sc_in);
        my $cpid = open3(*sc_in, my $co, my $ce,
            $shlib_wrap, $apps_openssl, @ccmd);
        print sc_in "Q\n";
        close(sc_in);
        {
            local $/;
            $cout = <$co>;
        }
        waitpid($cpid, 0);

        # The server exits after one connection, so read what it said.
        {
            local $/;
            $sout = <$so>;
        }
        waitpid($spid, 0);

        alarm 0;
    };
    print("case error: $@") if $@;
    return ($port, $cout // "", $sout // "");
}

# Client has: an MTC credential for the CA.  Server has: the CA, and requires
# a client certificate.
{
    my ($port, $cout, $sout) = run_case("-tai_chains", $chains);
    print("with-credential client output:\n$cout\n");
    print("with-credential server output:\n$sout\n");
    ok($port ne "0", "s_server started");
    # The CertificateRequest asked for the CA's trust anchor, 32473.1, whose
    # relative-OID bytes are 81 fd 59 01 in a one-entry list.
    ok($cout =~ /TLS server extension "trust anchors"/,
        "the server asked for trust anchors");
    ok($cout =~ /04 81 fd 59 01/,
        "it asked for the MTC CA's trust anchor");
    ok($cout =~ /Verify return code: 0 \(ok\)/,
        "the client verified the server");
    ok($sout =~ /Client certificate/, "the client authenticated");
    ok(cert_body($sout) eq cert_body(slurp($mtc_cred)),
        "the MTC credential is what the client sent");
}

# Client has: nothing.  Server has: the CA, and requires a client certificate.
{
    my ($port, $cout, $sout) = run_case();
    print("no-credential client output:\n$cout\n");
    print("no-credential server output:\n$sout\n");
    ok($sout !~ /Client certificate/,
        "no client certificate without a matching credential");
}
