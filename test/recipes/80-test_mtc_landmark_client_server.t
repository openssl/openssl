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
#
# A server holding a standalone certificate for the same CA as well chooses
# between the two.  A landmark group contains the CA's own trust anchor as well
# as its landmarks (section 8.2.1 of draft-ietf-plants-merkle-tree-certs), so a
# client advertising one may be sent either, and configuration order decides;
# those cases are run with the two in both orders.

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

plan tests => 46;

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

# The standalone (cosigned) credential of the same CA, for the cases where the
# server holds both and has to choose.
my $sa_cred = srctop_file("test", "mtc", "mtc-server.pem");
my $sa_key  = srctop_file("test", "mtc", "mtc-server-key.pem");

# The CA's trust anchor ID and log number, read from the subtree hash file's
# first line ("<id> <log> <start> <end> <hash>") so they are not duplicated here.
my ($mtc_oid, $mtc_log) = do {
    open(my $fh, "<", $mtc_subtrees) or die "cannot read $mtc_subtrees: $!";
    my @f = split(" ", <$fh>);
    ($f[0], $f[1]);
};
my $landmark_spec = "$mtc_oid:$mtc_log:$mtc_landmarks";

sub slurp {
    my ($file) = @_;
    open(my $fh, "<", $file) or die "cannot read $file: $!";
    local $/;
    my $text = <$fh>;
    close($fh);
    return $text;
}

sub spew {
    my ($file, $text) = @_;
    open(my $fh, ">", $file) or die "cannot write $file: $!";
    print $fh $text;
    close($fh);
    return $file;
}

# The base64 body of the one certificate in a chain file, or of the certificate
# the server sent, so that the two can be compared to see which was served.  A
# properties block does not match: its line reads "BEGIN CERTIFICATE PROPERTIES".
sub cert_body {
    my ($text) = @_;
    my $body;

    return "" if $text !~
        /-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s;
    $body = $1;
    $body =~ s/\s+//g;
    return $body;
}

# The landmarks the log has certificates for.
my $LAST = 10;

# The landmark-relative credential constructed from landmark $l.
sub landmark_cert {
    my ($l) = @_;

    return srctop_file("test", "mtc", "mtc-landmark-$l.pem");
}

# A server's -tai_chains file: each credential's properties block and
# certificate followed by the key it uses, in preference order, so that the
# file needs no separate -tai_keys.
sub server_file {
    my ($name, @creds) = @_;
    my $text = "";

    foreach my $cred (@creds) {
        $text .= slurp($cred) . slurp($cred eq $sa_cred ? $sa_key : $mtc_key);
    }
    return spew($name, $text);
}

# The client arguments for a relying party whose latest landmark is $l, with
# $w landmarks unexpired at the -attime cutoff: the log's published landmarks
# and the hashes of the unexpired landmarks' subtrees.  With none unexpired
# there are no hashes to give.
sub client_state {
    my ($l, $w) = @_;
    my $prefix = "mtc-landmark-$l-w$w";
    my @args = ("-mtc_landmarks", "$mtc_oid:$mtc_log:"
        . srctop_file("test", "mtc", "$prefix-landmarks.txt"));

    push(@args, "-mtc_subtrees",
        srctop_file("test", "mtc", "$prefix-subtrees.txt")) if $w > 0;
    return @args;
}

# Start an s_server holding chains, run one s_client with the given extra
# arguments, and return the accepted port and the client's stdout.
sub run_server_case {
    my ($chains, $keys, @client_extra) = @_;
    my $port = "0";
    my $out = "";

    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm 60;

        my @scmd = ("s_server", "-accept", "0", "-naccept", "1",
            "-cert", $srvcert, "-key", $srvkey,
            "-tai_chains", $chains, "-tls1_3");
        push(@scmd, "-tai_keys", $keys) if defined $keys;
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

# The original cases: the server holds only the landmark credential.
sub run_case {
    my (@client_extra) = @_;

    return run_server_case($mtc_cred, $mtc_key, @client_extra);
}

my $verify_ok = qr/Verify return code: 0 \(ok\)/;

# The verification result s_client reports.  0 is success, 21 is the RSA
# fallback the server sends when no MTC credential matched, which the client
# does not trust, and 110 is X509_V_ERR_MTC_NOT_TRUSTED: an MTC certificate was
# served and its subtree is not one the client has vetted.
sub verify_code {
    my ($code) = @_;

    return qr/Verify return code: $code \(/;
}

# Client has: landmark 1.  Server has: landmark 1.
{
    my ($port, $out) = run_case("-mtc_landmarks", $landmark_spec,
        "-mtc_subtrees", $mtc_subtrees);
    print("with-landmarks s_client output:\n$out\n");
    ok($port ne "0", "s_server started");
    ok($out =~ $verify_ok,
        "landmark MTC served and validated from its landmark group");
}

# Client has: landmark 1 with no hash for it, so CA signed.  Server has:
# landmark 1.
{
    my ($port, $out) = run_case("-mtc_landmarks", $landmark_spec);
    print("no-hash s_client output:\n$out\n");
    ok($out =~ verify_code(21),
        "landmark MTC fails without the vetted subtree hash");
}

# Client has: CA signed.  Server has: landmark 1.
{
    my ($port, $out) = run_case();
    print("no-landmark s_client output:\n$out\n");
    ok($out =~ verify_code(21),
        "landmark MTC not served to a client with no landmark state");
}

# Which credential is served follows what the client advertises, and where more
# than one matches, the order the credentials were configured in.  A landmark
# certificate from landmark L carries the pattern caID.2.N.{L-}, so it matches
# every client whose latest landmark is L or later, whether or not that client
# still holds landmark L; the standalone certificate carries caID.2.{0-}.{0-}
# and matches every client (section 8.2.1 of the Merkle Tree Certificates
# draft).  The body of each certificate, to compare against the one the server
# sent.
my %body = map { $_ => cert_body(slurp(landmark_cert($_))) } 1 .. $LAST;
my $ca_signed = cert_body(slurp($sa_cred));

my $landmark_first = server_file("landmark-first.pem",
    landmark_cert(1), $sa_cred);
my $standalone_first = server_file("standalone-first.pem",
    $sa_cred, landmark_cert(1));
my $all_landmarks = server_file("all-landmarks.pem",
    (map { landmark_cert($_) } reverse(1 .. $LAST)), $sa_cred);
my $holes_even = server_file("holes-even.pem",
    (map { landmark_cert($_) } 8, 6, 4, 2), $sa_cred);
my $holes_wide = server_file("holes-wide.pem",
    (map { landmark_cert($_) } 8, 5, 2), $sa_cred);
my $holes_wide_no_ca = server_file("holes-wide-no-ca.pem",
    map { landmark_cert($_) } 8, 5, 2);
my $ahead = server_file("ahead.pem",
    (map { landmark_cert($_) } 10, 9, 8), $sa_cred);
my $behind = server_file("behind.pem",
    (map { landmark_cert($_) } 2, 1), $sa_cred);
my $only_5 = server_file("only-5.pem", landmark_cert(5), $sa_cred);

# Landmark 1's certificate with the IANA-assigned id-alg-mtcProof as its
# signature algorithm; the log entry omits the signature algorithm, so its
# proof is landmark 1's.
my $iana_alg_cred = srctop_file("test", "mtc", "mtc-landmark-1-iana-alg.pem");
my $iana_alg = server_file("iana-alg.pem", $iana_alg_cred, $sa_cred);
my $iana_alg_body = cert_body(slurp($iana_alg_cred));

# Landmark 1's state, but with another landmark's hash recorded for [0, 4).
# It is a real hash of the right length, just not this subtree's, so the case
# fails only if the hash is compared and not merely present.
my $wrong_hash = (split(" ", slurp(srctop_file("test", "mtc",
    "mtc-landmark-5-w2-subtrees.txt"))))[4];
my $wrong_subtrees = spew("wrong-subtrees.txt",
    "$mtc_oid $mtc_log 0 4 $wrong_hash\n");

# Each case is the server's chain file, the client's arguments, the certificate
# body the server is expected to send (undefined where that is the RSA
# fallback, whose body is not one of the fixtures), the verification result the
# client is expected to report, and what to call it.  Client state (L, W) is a
# latest landmark of L with W landmarks unexpired.
foreach my $case (
    # Client has: (1, 2).  Server has: landmark 1, standalone.
    [ $landmark_first, [ client_state(1, 2) ], $body{1}, 0,
      "landmark certificate to a client holding its landmark" ],
    # Client has: no landmark state.  Server has: landmark 1, standalone.
    [ $landmark_first, [], $ca_signed, 0,
      "standalone certificate to a client with no landmark state" ],
    # Client has: (5, 0), every landmark expired.  Server has: landmark 1,
    # standalone.
    [ $landmark_first, [ client_state(5, 0) ], $ca_signed, 0,
      "a client whose landmarks all expired gets the standalone" ],
    # Client has: (1, 2).  Server has: standalone, landmark 1.
    [ $standalone_first, [ client_state(1, 2) ], $ca_signed, 0,
      "standalone certificate first is served in preference to the landmark" ],
    # Client has: no landmark state.  Server has: standalone, landmark 1.
    [ $standalone_first, [], $ca_signed, 0,
      "standalone certificate first, client with no landmark state" ],
    # Client has: (10, 2).  Server has: standalone, landmark 1.
    [ $standalone_first, [ client_state(10, 2) ], $ca_signed, 0,
      "standalone certificate first, client past the server's landmark" ],

    # Client has: (5, 2).  Server has: landmarks 10 down to 1, standalone.
    [ $all_landmarks, [ client_state(5, 2) ], $body{5}, 0,
      "the client's own landmark is served when the server has them all" ],
    # Client has: (10, 2).  Server has: landmarks 10 down to 1, standalone.
    [ $all_landmarks, [ client_state(10, 2) ], $body{10}, 0,
      "the newest landmark is served to a client up to date with it" ],
    # Client has: (1, 2).  Server has: landmarks 10 down to 1, standalone.
    [ $all_landmarks, [ client_state(1, 2) ], $body{1}, 0,
      "the oldest landmark is served to a client that far behind" ],
    # Client has: (5, 2).  Server has: landmarks 8, 6, 4, 2, standalone.
    [ $holes_even, [ client_state(5, 2) ], $body{4}, 0,
      "the landmark before the client's is served when the server skipped it" ],
    # Client has: (5, 2).  Server has: landmarks 10, 9, 8, standalone.
    [ $ahead, [ client_state(5, 2) ], $ca_signed, 0,
      "a server entirely ahead of the client serves the standalone" ],
    # Client has: (5, 4).  Server has: landmarks 2, 1, standalone.
    [ $behind, [ client_state(5, 4) ], $body{2}, 0,
      "a landmark three behind is served to a client still holding it" ],
    # Client has: (4, 4).  Server has: landmarks 8, 5, 2, standalone.
    [ $holes_wide, [ client_state(4, 4) ], $body{2}, 0,
      "the newest landmark at or before the client's is served across a hole" ],
    # Client has: (5, 1).  Server has: landmark 5, standalone.
    [ $only_5, [ client_state(5, 1) ], $body{5}, 0,
      "a client holding one landmark verifies a certificate from it" ],
    # Client has: (1, 2).  Server has: landmark 1 with the IANA-assigned
    # id-alg-mtcProof, standalone.
    [ $iana_alg, [ client_state(1, 2) ], $iana_alg_body, 0,
      "a landmark certificate with the IANA-assigned id-alg-mtcProof" ],

    # The landmark cutoff: each client below has let the landmark it is sent
    # expire, so it no longer trusts that landmark's subtrees.
    # Client has: (5, 2).  Server has: landmarks 2, 1, standalone.
    [ $behind, [ client_state(5, 2) ], $body{2}, 110,
      "a landmark the client let expire is served and does not verify" ],
    # Client has: (4, 2).  Server has: landmarks 8, 5, 2, standalone.
    [ $holes_wide, [ client_state(4, 2) ], $body{2}, 110,
      "a landmark across a hole the client let expire does not verify" ],
    # Client has: (4, 2).  Server has: landmarks 8, 5, 2.
    [ $holes_wide_no_ca, [ client_state(4, 2) ], $body{2}, 110,
      "without a standalone certificate the expired landmark is still served" ],
    # Client has: (6, 1).  Server has: landmark 5, standalone.
    [ $only_5, [ client_state(6, 1) ], $body{5}, 110,
      "a client holding one landmark does not verify the one before it" ],
    # Client has: (10, 2).  Server has: landmark 1, standalone.
    [ $landmark_first, [ client_state(10, 2) ], $body{1}, 110,
      "a client far past the server's landmark does not verify it" ],

    # Client has: (1, 2), with the wrong hash for its subtree.  Server has:
    # landmark 1, standalone.
    [ $landmark_first,
      [ "-mtc_landmarks", "$mtc_oid:$mtc_log:$mtc_landmarks",
        "-mtc_subtrees", $wrong_subtrees ], $body{1}, 110,
      "a hash vetted for the subtree but not its own does not verify" ],
) {
    my ($chains, $client, $expect, $code, $what) = @$case;
    my ($port, $out) = run_server_case($chains, undef, @$client);

    print("s_client output ($what):\n$out\n");
    ok($out =~ verify_code($code), "verify $code: $what");
    ok(!defined $expect || cert_body($out) eq $expect, "served: $what");
}
