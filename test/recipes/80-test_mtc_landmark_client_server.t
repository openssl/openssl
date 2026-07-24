#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# End-to-end test of a landmark-relative (signatureless) Merkle Tree Certificate
# validated TLS 1.3 connection.  The server serves the landmark leaf; the client
# trusts the MTC CA (-mtc_cas) and is given the leaf's trusted subtree
# (-mtc_subtrees), which a signatureless leaf needs to verify.  A second run
# without -mtc_subtrees must fail, proving the subtree is load-bearing (and that
# the served leaf really is signatureless, not a standalone cosigned cert).
# Server authentication only.

use strict;
use warnings;

use IPC::Open3;
use OpenSSL::Test qw/:DEFAULT srctop_file bldtop_file/;
use OpenSSL::Test::Utils;

my $test_name = "test_mtc_landmark_client_server";
setup($test_name);

plan skip_all => "$test_name requires sock enabled" if disabled("sock");
plan skip_all => "$test_name requires TLSv1.3 enabled" if disabled("tls1_3");
plan skip_all => "$test_name requires ML-DSA enabled" if disabled("ml-dsa");
plan skip_all => "$test_name is not available on Windows or VMS"
    if $^O =~ /^(VMS|MSWin32|msys)$/;

plan tests => 4;

my $shlib_wrap   = bldtop_file("util", "shlib_wrap.sh");
my $apps_openssl = bldtop_file("apps", "openssl");

# A fallback (ubiquitous) certificate so the server can start, plus the landmark
# MTC credential it serves when the client requests its trust anchor.
my $srvcert = srctop_file("test", "certs", "servercert.pem");
my $srvkey  = srctop_file("test", "certs", "serverkey.pem");

# The landmark-relative MTC credential, its key, the MTC CA (shared with the
# standalone test), the log's published active landmarks, and the vetted hashes
# of the landmark's subtrees.
my $mtc_cred      = srctop_file("test", "mtc", "mtc-landmark-1.pem");
my $mtc_key       = srctop_file("test", "mtc", "mtc-landmark-key.pem");
my $mtc_ca        = srctop_file("test", "mtc", "mtc-ca-cert.pem");
my $mtc_landmarks = srctop_file("test", "mtc",
    "mtc-landmark-1-w2-landmarks.txt");
my $mtc_subtrees  = srctop_file("test", "mtc",
    "mtc-landmark-1-w2-subtrees.txt");

# The CA's trust anchor ID and log number, read from the subtree hash file's
# first line ("<id> <log> <start> <end> <hash>") so they are not duplicated here.
my ($mtc_oid, $mtc_log) = do {
    open(my $fh, "<", $mtc_subtrees) or die "cannot read $mtc_subtrees: $!";
    my @f = split(" ", <$fh>);
    ($f[0], $f[1]);
};
my $landmark_spec = "$mtc_oid:$mtc_log:$mtc_landmarks";

# Start an s_server with the landmark credential, run one s_client with the
# given extra arguments, and return the accepted port and the client's stdout.
sub run_case {
    my (@client_extra) = @_;
    my $port = "0";
    my $out = "";

    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm 60;

        my @scmd = ("s_server", "-accept", "0", "-naccept", "1",
            "-cert", $srvcert, "-key", $srvkey,
            "-tai_chains", $mtc_cred, "-tai_keys", $mtc_key,
            "-tls1_3");
        my $spid = open3(my $si, my $so, my $se,
            $shlib_wrap, $apps_openssl, @scmd);
        while (<$so>) {
            if (/^ACCEPT 0.0.0.0:(\d+)/ || /^ACCEPT \[::\]:(\d+)/) {
                $port = $1;
                last;
            }
        }

        # -attime pins verification to a fixed instant inside the fixtures'
        # validity (2020..2030), so the test does not expire when the certs do.
        my @ccmd = ("s_client", "-connect", "localhost:$port",
            "-mtc_cas", $mtc_ca,
            "-no-CAfile", "-no-CApath", "-no-CAstore",
            "-attime", "1735689600",
            "-tls1_3", "-nameopt", "RFC2253", @client_extra);
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

        alarm 0;
    };
    print("case error: $@") if $@;
    return ($port, $out // "");
}

my $verify_ok = qr/Verify return code: 0 \(ok\)/;

# With the active landmarks and the vetted subtree hash: the client requests the
# landmark group, the server selects the landmark credential for it, and the
# signatureless leaf validates against the client's trusted subtree.
{
    my ($port, $out) = run_case("-mtc_landmarks", $landmark_spec,
        "-mtc_subtrees", $mtc_subtrees);
    print("with-landmarks s_client output:\n$out\n");
    ok($port ne "0", "s_server started");
    ok($out =~ $verify_ok,
        "landmark MTC served and validated from its landmark group");
}

# With the window loaded but no vetted hash, the subtree is active yet unusable,
# so the client does not request the landmark group and cannot verify the leaf.
{
    my ($port, $out) = run_case("-mtc_landmarks", $landmark_spec);
    print("no-hash s_client output:\n$out\n");
    ok($out !~ $verify_ok,
        "landmark MTC fails without the vetted subtree hash");
}

# With no landmark state at all, the client requests only the CA's own trust
# anchor, which the landmark credential does not carry, so the server cannot
# select it and the leaf is never served.
{
    my ($port, $out) = run_case();
    print("no-landmark s_client output:\n$out\n");
    ok($out !~ $verify_ok,
        "landmark MTC not served to a client with no landmark state");
}
