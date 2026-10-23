#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# End-to-end test of a Merkle Tree Certificate (draft-ietf-plants-merkle-tree-
# certs) validated TLS 1.3 connection.  The client trusts an MTC CA and requests
# its trust anchor ID; the server serves the MTC certificate issued by that CA;
# the client validates it against the MTC CA.  Server authentication only.

use strict;
use warnings;

use IPC::Open3;
use OpenSSL::Test qw/:DEFAULT srctop_file bldtop_file/;
use OpenSSL::Test::Utils;

my $test_name = "test_mtc_client_server";
setup($test_name);

plan skip_all => "$test_name requires sock enabled" if disabled("sock");
plan skip_all => "$test_name requires TLSv1.3 enabled" if disabled("tls1_3");
plan skip_all => "$test_name requires ML-DSA enabled" if disabled("ml-dsa");
plan skip_all => "$test_name is not available on Windows or VMS"
    if $^O =~ /^(VMS|MSWin32|msys)$/;

# The client cases: extra s_client options and the verify return code each
# yields.  mtc-server.pem carries the CA cosignature only, so trusting the
# additional cosigners changes nothing until a quorum of them is required, and
# then the certificate is short of it (X509_V_ERR_MTC_COSIGNER_QUORUM, 111).
my $mtc_cosigners = srctop_file("test", "mtc", "mtc-cosigners.pem");
my @cases = (
    [ [], 0, "MTC certificate served and validated end to end" ],
    [ [ "-mtc_cosigners", $mtc_cosigners, "-mtc_cosigner_quorum", "0" ], 0,
      "trusted cosigners with no quorum leave the CA cosignature sufficient" ],
    [ [ "-mtc_cosigners", $mtc_cosigners, "-mtc_cosigner_quorum", "1" ], 111,
      "a quorum of one is not met by the CA cosignature alone" ],
);

plan tests => 2 * scalar @cases;

my $shlib_wrap   = bldtop_file("util", "shlib_wrap.sh");
my $apps_openssl = bldtop_file("apps", "openssl");

# A fallback (ubiquitous) certificate so the server can start, plus the MTC
# credential it serves when the client requests its trust anchor.
my $srvcert = srctop_file("test", "certs", "servercert.pem");
my $srvkey  = srctop_file("test", "certs", "serverkey.pem");

# The keyed, standalone MTC credential and the CA that issued it.  mtc-server.pem
# is a CERTIFICATE PROPERTIES block carrying trust anchor ID 32473.1 followed by
# the MTC leaf; mtc-server-key.pem is the leaf's key; mtc-ca-cert.pem is the MTC
# CA certificate the client trusts.
my $mtc_cred = srctop_file("test", "mtc", "mtc-server.pem");
my $mtc_key  = srctop_file("test", "mtc", "mtc-server-key.pem");
my $mtc_ca   = srctop_file("test", "mtc", "mtc-ca-cert.pem");

foreach my $case (@cases) {
    my ($copts, $code, $desc) = @$case;
    my $port = "0";
    my $out = "";

    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm 60;

        my @scmd = ("s_server", "-accept", "0", "-naccept", "1",
            "-cert", $srvcert, "-key", $srvkey,
            "-tai_chains", $mtc_cred, "-tai_keys", $mtc_key,
            "-tls1_3");
        print("s_server @scmd\n");
        my $spid = open3(my $si, my $so, my $se,
            $shlib_wrap, $apps_openssl, @scmd);
        while (<$so>) {
            print($_);
            if (/^ACCEPT 0.0.0.0:(\d+)/ || /^ACCEPT \[::\]:(\d+)/) {
                $port = $1;
                last;
            }
        }

        # The client trusts only the MTC CA (no X.509 trust anchors), so a clean
        # verify can only come from validating the served MTC certificate.
        # -attime pins verification to a fixed instant inside the fixtures'
        # validity, so the test does not expire when the certificates do.
        my @ccmd = ("s_client", "-connect", "localhost:$port",
            "-mtc_cas", $mtc_ca, @$copts,
            "-no-CAfile", "-no-CApath", "-no-CAstore",
            "-attime", "1735689600",
            "-tls1_3", "-nameopt", "RFC2253");
        print("s_client @ccmd\n");
        local (*sc_in);
        my $cpid = open3(*sc_in, my $co, my $ce,
            $shlib_wrap, $apps_openssl, @ccmd);
        print sc_in "Q\n";
        close(sc_in);
        {
            local $/;
            $out = <$co>;
        }
        waitpid($cpid, 0);
        kill 'HUP', $spid if kill(0, $spid);
        waitpid($spid, 0);
        print("s_client output:\n$out\n");

        alarm 0;
    };
    print("test error: $@") if $@;

    ok($port ne "0", "s_server started");
    ok($out =~ /Verify return code: $code \(/, $desc);
}
