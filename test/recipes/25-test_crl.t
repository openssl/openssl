#! /usr/bin/env perl
# Copyright 2015-2021 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_crl");

plan tests => 11;

require_ok(srctop_file('test','recipes','tconversion.pl'));

my $pem = srctop_file("test/certs", "cyrillic_crl.pem");
my $out = "cyrillic_crl.out";
my $utf = srctop_file("test/certs", "cyrillic_crl.utf8");

subtest 'crl conversions' => sub {
    tconversion( -type => "crl", -in => srctop_file("test","testcrl.pem") );
};

ok(run(test(['crltest'])));

ok(compare1stline([qw{openssl crl -noout -fingerprint -in},
                   srctop_file('test', 'testcrl.pem')],
                  'SHA1 Fingerprint=BA:F4:1B:AD:7A:9B:2F:09:16:BC:60:A7:0E:CE:79:2E:36:00:E7:B2'));
ok(compare1stline([qw{openssl crl -noout -fingerprint -sha256 -in},
                   srctop_file('test', 'testcrl.pem')],
                  'SHA2-256 Fingerprint=B3:A9:FD:A7:2E:8C:3D:DF:D0:F1:C3:1A:96:60:B5:FD:B0:99:7C:7F:0E:E4:34:F5:DB:87:62:36:BC:F1:BC:1B'));
ok(compare1stline([qw{openssl crl -noout -hash -in},
                   srctop_file('test', 'testcrl.pem')],
                  '106cd822'));

ok(compare1stline_stdin([qw{openssl crl -hash -noout}],
                        srctop_file("test","testcrl.pem"),
                        '106cd822'),
   "crl piped input test");

ok(!run(app(["openssl", "crl", "-text", "-in", $pem, "-inform", "DER",
             "-out", $out, "-nameopt", "utf8"])));
ok(run(app(["openssl", "crl", "-text", "-in", $pem, "-inform", "PEM",
            "-out", $out, "-nameopt", "utf8"])));
is(cmp_text($out, srctop_file("test/certs", "cyrillic_crl.utf8")),
   0, 'Comparing utf8 output');

subtest 'CRL RFC5280 extension enforcement failures' => sub {
    # v1 CRL with extensions => version mismatch
    my $v1 = srctop_file('test','testcrl_v1_ext.pem');
    ok(! run(app(["openssl","crl","-in",$v1,"-noout","-check-extensions"])),
        'v1 CRL with extensions should fail');
    like(join('', @{run(app(["openssl","crl","-in",$v1,"-noout","-check-extensions"], capture=>1))}),
        qr/Extensions are only valid in a v2 CRL/,
        'version mismatch error');

    # Authority Key Identifier (AKI)
    my @aki_tests = (
        ['missing AKI' => 'testcrl_missing_aki.pem',
            qr/Authority Key Identifier .* MUST appear exactly once/],
        ['AKI marked critical' > 'testcrl_aki_critical.pem',
            qr/Authority Key Identifier .* MUST NOT be marked critical/],
        ['empty keyIdentifier' => 'testcrl_aki_empty_keyid.pem',
            qr/MUST contain a non-empty keyIdentifier/],
        ['includes certIssuer' => 'testcrl_aki_certissuer.pem',
            qr/MUST NOT include authorityCertIssuer/],
        ['includes certSerialNumber' => 'testcrl_aki_certserial.pem',
            qr/MUST NOT include authorityCertSerialNumber/],
    );
    for my $t (@aki_tests) {
        my ($desc, $file, $pattern) = @$t;
        my $pemfile = srctop_file('test',$file);
        ok(! run(app(["openssl","crl","-in",$pemfile,"-noout","-check-extensions"])),
            "$desc should fail");
        like(join('', @{run(app(["openssl","crl","-in",$pemfile,"-noout","-check-extensions"], capture=>1))}),
            $pattern,
            "$desc error");
    }

    # CRL Number
    my $no_crlnum = srctop_file('test','testcrl_missing_crlnum.pem');
    ok(! run(app(["openssl","crl","-in",$no_crlnum,"-noout","-check-extensions"])),
        'missing CRL Number should fail');
    like(join('', @{run(app(["openssl","crl","-in",$no_crlnum,"-noout","-check-extensions"], capture=>1))}),
        qr/CRL Number .* MUST appear exactly once/,
        'CRL Number cardinality error');
    my $crlnum_crit = srctop_file('test','testcrl_crlnum_critical.pem');
    ok(! run(app(["openssl","crl","-in",$crlnum_crit,"-noout","-check-extensions"])),
        'CRL Number marked critical should fail');
    like(join('', @{run(app(["openssl","crl","-in",$crlnum_crit,"-noout","-check-extensions"], capture=>1))}),
        qr/CRL Number .* MUST NOT be marked critical/,
        'CRL Number criticality error');

    # Issuer Alternative Name (IAN)
    my $ian2 = srctop_file('test','testcrl_ian_twice.pem');
    ok(! run(app(["openssl","crl","-in",$ian2,"-noout","-check-extensions"])),
        'duplicate Issuer Alternative Name should warn');
    like(join('', @{run(app(["openssl","crl","-in",$ian2,"-noout","-check-extensions"], capture=>1))}),
        qr/Issuer Alternative Name .* at most once/,
        'IAN duplicate count error');
    like(join('', @{run(app(["openssl","crl","-in",$ian2,"-noout","-check-extensions"], capture=>1))}),
        qr/Issuer Alternative Name .* SHOULD NOT be critical/,
        'IAN criticality error');

    # Delta CRL Indicator
    my $dnc = srctop_file('test','testcrl_delta_noncrit.pem');
    ok(! run(app(["openssl","crl","-in",$dnc,"-noout","-check-extensions"])),
        'Delta CRL missing criticality should fail');
    like(join('', @{run(app(["openssl","crl","-in",$dnc,"-noout","-check-extensions"], capture=>1))}),
        qr/Delta CRL Indicator MUST be marked critical/,
        'Delta CRL criticality error');
    my $d2 = srctop_file('test','testcrl_delta_twice.pem');
    ok(! run(app(["openssl","crl","-in",$d2,"-noout","-check-extensions"])),
        'duplicate Delta CRL Indicator should warn');
    like(join('', @{run(app(["openssl","crl","-in",$d2,"-noout","-check-extensions"], capture=>1))}),
        qr/MUST appear at most once \(found 2\)/,
        'Delta CRL duplicate count error');

    # Issuing Distribution Point (IDP)
    my $idpnc = srctop_file('test','testcrl_idp_noncrit.pem');
    ok(! run(app(["openssl","crl","-in",$idpnc,"-noout","-check-extensions"])),
        'IDP missing criticality should fail');
    like(join('', @{run(app(["openssl","crl","-in",$idpnc,"-noout","-check-extensions"], capture=>1))}),
        qr/Issuing Distribution Point MUST be marked critical/,
        'IDP criticality error');
    my $idp2 = srctop_file('test','testcrl_idp_twice.pem');
    ok(! run(app(["openssl","crl","-in",$idp2,"-noout","-check-extensions"])),
        'duplicate IDP should warn');
    like(join('', @{run(app(["openssl","crl","-in",$idp2,"-noout","-check-extensions"], capture=>1))}),
        qr/MUST appear at most once \(found 2\)/,
        'IDP duplicate count error');

    # Freshest CRL
    my $f_in_delta = srctop_file('test','testcrl_freshest_in_delta.pem');
    ok(! run(app(["openssl","crl","-in",$f_in_delta,"-noout","-check-extensions"])),
        'Freshest CRL in delta should fail');
    like(join('', @{run(app(["openssl","crl","-in",$f_in_delta,"-noout","-check-extensions"], capture=>1))}),
        qr/Freshest CRL MUST NOT appear in a delta CRL/,
        'Freshest-in-delta error');
    my $f2 = srctop_file('test','testcrl_freshest_twice.pem');
    ok(! run(app(["openssl","crl","-in",$f2,"-noout","-check-extensions"])),
        'duplicate Freshest CRL should warn');
    like(join('', @{run(app(["openssl","crl","-in",$f2,"-noout","-check-extensions"], capture=>1))}),
        qr/MUST appear at most once \(found 2\)/,
        'Freshest duplicate count error');
    like(join('', @{run(app(["openssl","crl","-in",$f2,"-noout","-check-extensions"], capture=>1))}),
        qr/SHOULD NOT be critical/,
        'Freshest criticality error');

    # Authority Information Access (AIA)
    my $aia2 = srctop_file('test','testcrl_infoaccess_twice.pem');
    ok(! run(app(["openssl","crl","-in",$aia2,"-noout","-check-extensions"])),
        'duplicate Authority Information Access should warn');
    like(join('', @{run(app(["openssl","crl","-in",$aia2,"-noout","-check-extensions"], capture=>1))}),
        qr/MUST appear at most once \(found 2\)/,
        'AIA duplicate count error');
    like(join('', @{run(app(["openssl","crl","-in",$aia2,"-noout","-check-extensions"], capture=>1))}),
        qr/SHOULD NOT be critical/,
        'AIA criticality error');

    # Unknown critical extension
    my $unk = srctop_file('test','testcrl_unknown_crit.pem');
    ok(! run(app(["openssl","crl","-in",$unk,"-noout","-check-extensions"])),
        'unknown critical extension should fail');
    like(join('', @{run(app(["openssl","crl","-in",$unk,"-noout","-check-extensions"], capture=>1))}),
        qr/unknown critical CRL extension/,
        'Unknown critical extension error');

    1;
};

sub compare1stline {
    my ($cmdarray, $str) = @_;
    my @lines = run(app($cmdarray), capture => 1);

    return 1 if $lines[0] =~ m|^\Q${str}\E\R$|;
    note "Got      ", $lines[0];
    note "Expected ", $str;
    return 0;
}

sub compare1stline_stdin {
    my ($cmdarray, $infile, $str) = @_;
    my @lines = run(app($cmdarray, stdin => $infile), capture => 1);

    return 1 if $lines[0] =~ m|^\Q${str}\E\R$|;
    note "Got      ", $lines[0];
    note "Expected ", $str;
    return 0;
}
