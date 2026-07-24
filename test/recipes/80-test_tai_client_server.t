#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# End-to-end test of trust anchor identifier (draft-ietf-tls-trust-anchor-ids)
# negotiation between the s_client and s_server apps for conventional (non-MTC)
# certificates.  The client advertises the trust anchor IDs of the decorated
# CAs it loads; the server serves a matching trust anchor decorated chain when
# it has one, and its ubiquitous fallback certificate otherwise.

use strict;
use warnings;

use IPC::Open3;
use OpenSSL::Test qw/:DEFAULT srctop_file bldtop_file/;
use OpenSSL::Test::Utils;

my $test_name = "test_tai_client_server";
setup($test_name);

plan skip_all => "$test_name requires sock enabled" if disabled("sock");
plan skip_all => "$test_name requires TLSv1.3 enabled" if disabled("tls1_3");
plan skip_all => "$test_name needs EC or DH enabled"
    if disabled("ec") && disabled("dh");
plan skip_all => "$test_name is not available on Windows or VMS"
    if $^O =~ /^(VMS|MSWin32|msys)$/;

plan tests => 8;

my $shlib_wrap   = bldtop_file("util", "shlib_wrap.sh");
my $apps_openssl = bldtop_file("apps", "openssl");

my $rootcert  = srctop_file("test", "certs", "rootcert.pem");
my $cacert    = srctop_file("test", "certs", "ca-cert.pem");
my $eecert    = srctop_file("test", "certs", "ee-cert.pem");
my $eekey     = srctop_file("test", "certs", "ee-key.pem");
my $srvcert   = srctop_file("test", "certs", "servercert.pem");
my $srvkey    = srctop_file("test", "certs", "serverkey.pem");

# Trust anchor IDs: 32473.1 is served by the server; 32473.9 is not.
my $tai_served = "32473.1";
my $tai_absent = "32473.9";

# Generated fixtures (written to the test's working directory).  The trust
# anchor for an ID is the CA named by it (here ca-cert, the issuer of ee-cert),
# so a client that requests the ID trusts that CA directly (a partial chain).
# The fallback (servercert) chains to the separate Root CA.
my $srv_tai  = "server-tai.pem";      # the server's TAI credential (ee-cert)
my $ca_ta1   = "ca-ta-served.pem";    # client trusts CA, advertises 32473.1
my $root_ta9 = "root-ta-absent.pem";  # client trusts Root, advertises 32473.9
my $ca_ta9   = "ca-ta-absent.pem";    # client trusts CA only, advertises 32473.9

# openssl app wrapper.
sub openssl_ok {
    my ($desc, @args) = @_;
    return run(app([@args]));
}

# Build the fixtures with the generate_tai_chain command.
openssl_ok("decorate server chain", "openssl", "generate_tai_chain",
    "-chain", $eecert, "-oid", $tai_served, "-out", $srv_tai)
    or BAIL_OUT("could not build server TAI chain");
openssl_ok("decorate served ca", "openssl", "generate_tai_chain",
    "-chain", $cacert, "-oid", $tai_served, "-out", $ca_ta1)
    or BAIL_OUT("could not decorate ca (served)");
openssl_ok("decorate absent root", "openssl", "generate_tai_chain",
    "-chain", $rootcert, "-oid", $tai_absent, "-out", $root_ta9)
    or BAIL_OUT("could not decorate root (absent)");
openssl_ok("decorate absent ca", "openssl", "generate_tai_chain",
    "-chain", $cacert, "-oid", $tai_absent, "-out", $ca_ta9)
    or BAIL_OUT("could not decorate ca (absent)");

# Start an s_server with the fallback certificate and the TAI credential, run
# one s_client with the given -CAfile, and return the client's stdout together
# with the accepted port.
sub run_case {
    my ($client_ca) = @_;
    my $port = "0";
    my $out = "";

    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm 60;

        my @scmd = ("s_server", "-accept", "0", "-naccept", "1",
            "-cert", $srvcert, "-key", $srvkey,
            "-tai_chains", $srv_tai, "-tai_keys", $eekey,
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

        # -partial_chain lets a client trust the named CA directly, as a trust
        # anchor, without also trusting the root above it.  It does not affect
        # the fallback cases, which chain fully to a trusted root.
        my @ccmd = ("s_client", "-connect", "localhost:$port",
            "-CAfile", $client_ca, "-tls1_3", "-partial_chain",
            "-nameopt", "RFC2253");
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
    print("case error: $@") if $@;
    return ($port, $out // "");
}

my $verify_ok  = qr/Verify return code: 0 \(ok\)/;
# The trust anchor leaf (ee-cert) is issued by "CA"; the fallback (servercert)
# is issued by "Root CA".  Only a chain containing the TAI leaf has an issuer
# line of exactly "CN=CA" (RFC2253, forced with -nameopt), so it distinguishes
# which credential the server served ("CN=Root CA" does not match).
my $tai_served_leaf = qr/^\s*i:CN=CA$/m;

# 1. Client requests a trust anchor the server has: the TAI chain is served.
{
    my ($port, $out) = run_case($ca_ta1);
    ok($port ne "0", "matched: server started");
    ok($out =~ $verify_ok && $out =~ $tai_served_leaf,
        "matched: server serves the trust anchor chain, verified");
}

# 2. Client requests a trust anchor the server lacks, but trusts the fallback:
#    the ubiquitous certificate is served and verifies.
{
    my ($port, $out) = run_case($root_ta9);
    ok($port ne "0", "unmatched/trusted: server started");
    ok($out =~ $verify_ok && $out !~ $tai_served_leaf,
        "unmatched: server serves the fallback certificate, verified");
}

# 3. Client requests a trust anchor the server lacks and does not trust the
#    fallback: the fallback is served but fails to verify.
{
    my ($port, $out) = run_case($ca_ta9);
    ok($port ne "0", "unmatched/untrusted: server started");
    ok($out !~ $verify_ok && $out !~ $tai_served_leaf,
        "untrusted fallback: served but verification fails");
}

# 4. Baseline: client advertises no trust anchor and trusts the fallback.
{
    my ($port, $out) = run_case($rootcert);
    ok($port ne "0", "baseline: server started");
    ok($out =~ $verify_ok && $out !~ $tai_served_leaf,
        "baseline: fallback served and verified with no trust anchors");
}
