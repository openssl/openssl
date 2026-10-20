#! /usr/bin/env perl
# Copyright 2015-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use POSIX;
use File::Spec::Functions qw/devnull catfile/;
use File::Basename;
use File::Copy;
use File::Compare qw/compare/;
use OpenSSL::Test qw/:DEFAULT with pipe srctop_dir data_file/;
use OpenSSL::Test::Utils;

setup("test_ocsp");

plan skip_all => "OCSP is not supported by this OpenSSL build"
    if disabled("ocsp");

my $ocspdir=srctop_dir("test", "ocsp-tests");
# 17 December 2012 so we don't get certificate expiry errors.
my @check_time=("-attime", "1355875200");

sub test_ocsp {
    my $title = shift;
    my $inputfile = shift;
    my $CAfile = shift;
    my $untrusted = shift;
    if ($untrusted eq "") {
        $untrusted = $CAfile;
    }
    my $expected_exit = shift;
    my $nochecks = shift;
    my $opt_untrusted = shift // "-verify_other";
    my $outputfile = basename($inputfile, '.ors') . '.dat';

    run(app(["openssl", "base64", "-d",
             "-in", catfile($ocspdir,$inputfile),
             "-out", $outputfile]));
    my @certopt = ($opt_untrusted, catfile($ocspdir, $untrusted));
    with({ exit_checker => sub { return shift == $expected_exit; } },
         sub { ok(run(app(["openssl", "ocsp", "-respin", $outputfile,
                           "-partial_chain", @check_time,
                           "-CAfile", catfile($ocspdir, $CAfile),
                           @certopt,
                           "-no-CApath", "-no-CAstore",
                           $nochecks ? "-no_cert_checks" : ()])),
                  $title); });
}

plan tests => 16;

subtest "=== VALID OCSP RESPONSES ===" => sub {
    plan tests => 7;

    test_ocsp("NON-DELEGATED; Intermediate CA -> EE",
              "ND1.ors", "ND1_Issuer_ICA.pem", "", 0, 0);
    test_ocsp("NON-DELEGATED; Root CA -> Intermediate CA",
              "ND2.ors", "ND2_Issuer_Root.pem", "", 0, 0);
    test_ocsp("NON-DELEGATED; Root CA -> EE",
              "ND3.ors", "ND3_Issuer_Root.pem", "", 0, 0);
    test_ocsp("NON-DELEGATED; 3-level CA hierarchy",
              "ND1.ors", "ND1_Cross_Root.pem", "ND1_Issuer_ICA-Cross.pem", 0, 0);
    test_ocsp("DELEGATED; Intermediate CA -> EE",
              "D1.ors", "D1_Issuer_ICA.pem", "", 0, 0);
    test_ocsp("DELEGATED; Root CA -> Intermediate CA",
              "D2.ors", "D2_Issuer_Root.pem", "", 0, 0);
    test_ocsp("DELEGATED; Root CA -> EE",
              "D3.ors", "D3_Issuer_Root.pem", "", 0, 0);
};

subtest "=== INVALID SIGNATURE on the OCSP RESPONSE ===" => sub {
    plan tests => 6;

    test_ocsp("NON-DELEGATED; Intermediate CA -> EE",
              "ISOP_ND1.ors", "ND1_Issuer_ICA.pem", "", 1, 0);
    test_ocsp("NON-DELEGATED; Root CA -> Intermediate CA",
              "ISOP_ND2.ors", "ND2_Issuer_Root.pem", "", 1, 0);
    test_ocsp("NON-DELEGATED; Root CA -> EE",
              "ISOP_ND3.ors", "ND3_Issuer_Root.pem", "", 1, 0);
    test_ocsp("DELEGATED; Intermediate CA -> EE",
              "ISOP_D1.ors", "D1_Issuer_ICA.pem", "", 1, 0);
    test_ocsp("DELEGATED; Root CA -> Intermediate CA",
              "ISOP_D2.ors", "D2_Issuer_Root.pem", "", 1, 0);
    test_ocsp("DELEGATED; Root CA -> EE",
              "ISOP_D3.ors", "D3_Issuer_Root.pem", "", 1, 0);
};

subtest "=== WRONG RESPONDERID in the OCSP RESPONSE ===" => sub {
    plan tests => 6;

    test_ocsp("NON-DELEGATED; Intermediate CA -> EE",
              "WRID_ND1.ors", "ND1_Issuer_ICA.pem", "", 1, 0);
    test_ocsp("NON-DELEGATED; Root CA -> Intermediate CA",
              "WRID_ND2.ors", "ND2_Issuer_Root.pem", "", 1, 0);
    test_ocsp("NON-DELEGATED; Root CA -> EE",
              "WRID_ND3.ors", "ND3_Issuer_Root.pem", "", 1, 0);
    test_ocsp("DELEGATED; Intermediate CA -> EE",
              "WRID_D1.ors", "D1_Issuer_ICA.pem", "", 1, 0);
    test_ocsp("DELEGATED; Root CA -> Intermediate CA",
              "WRID_D2.ors", "D2_Issuer_Root.pem", "", 1, 0);
    test_ocsp("DELEGATED; Root CA -> EE",
              "WRID_D3.ors", "D3_Issuer_Root.pem", "", 1, 0);
};

subtest "=== WRONG ISSUERNAMEHASH in the OCSP RESPONSE ===" => sub {
    plan tests => 6;

    test_ocsp("NON-DELEGATED; Intermediate CA -> EE",
              "WINH_ND1.ors", "ND1_Issuer_ICA.pem", "", 1, 0);
    test_ocsp("NON-DELEGATED; Root CA -> Intermediate CA",
              "WINH_ND2.ors", "ND2_Issuer_Root.pem", "", 1, 0);
    test_ocsp("NON-DELEGATED; Root CA -> EE",
              "WINH_ND3.ors", "ND3_Issuer_Root.pem", "", 1, 0);
    test_ocsp("DELEGATED; Intermediate CA -> EE",
              "WINH_D1.ors", "D1_Issuer_ICA.pem", "", 1, 0);
    test_ocsp("DELEGATED; Root CA -> Intermediate CA",
              "WINH_D2.ors", "D2_Issuer_Root.pem", "", 1, 0);
    test_ocsp("DELEGATED; Root CA -> EE",
              "WINH_D3.ors", "D3_Issuer_Root.pem", "", 1, 0);
};

subtest "=== WRONG ISSUERKEYHASH in the OCSP RESPONSE ===" => sub {
    plan tests => 6;

    test_ocsp("NON-DELEGATED; Intermediate CA -> EE",
              "WIKH_ND1.ors", "ND1_Issuer_ICA.pem", "", 1, 0);
    test_ocsp("NON-DELEGATED; Root CA -> Intermediate CA",
              "WIKH_ND2.ors", "ND2_Issuer_Root.pem", "", 1, 0);
    test_ocsp("NON-DELEGATED; Root CA -> EE",
              "WIKH_ND3.ors", "ND3_Issuer_Root.pem", "", 1, 0);
    test_ocsp("DELEGATED; Intermediate CA -> EE",
              "WIKH_D1.ors", "D1_Issuer_ICA.pem", "", 1, 0);
    test_ocsp("DELEGATED; Root CA -> Intermediate CA",
              "WIKH_D2.ors", "D2_Issuer_Root.pem", "", 1, 0);
    test_ocsp("DELEGATED; Root CA -> EE",
              "WIKH_D3.ors", "D3_Issuer_Root.pem", "", 1, 0);
};

subtest "=== WRONG KEY in the DELEGATED OCSP SIGNING CERTIFICATE ===" => sub {
    plan tests => 3;

    test_ocsp("DELEGATED; Intermediate CA -> EE",
              "WKDOSC_D1.ors", "D1_Issuer_ICA.pem", "", 1, 0);
    test_ocsp("DELEGATED; Root CA -> Intermediate CA",
              "WKDOSC_D2.ors", "D2_Issuer_Root.pem", "", 1, 0);
    test_ocsp("DELEGATED; Root CA -> EE",
              "WKDOSC_D3.ors", "D3_Issuer_Root.pem", "", 1, 0);
};

subtest "=== INVALID SIGNATURE on the DELEGATED OCSP SIGNING CERTIFICATE ===" => sub {
    plan tests => 6;

    test_ocsp("DELEGATED; Intermediate CA -> EE",
              "ISDOSC_D1.ors", "D1_Issuer_ICA.pem", "", 1, 0);
    test_ocsp("DELEGATED; Root CA -> Intermediate CA",
              "ISDOSC_D2.ors", "D2_Issuer_Root.pem", "", 1, 0);
    test_ocsp("DELEGATED; Root CA -> EE",
              "ISDOSC_D3.ors", "D3_Issuer_Root.pem", "", 1, 0);
    test_ocsp("DELEGATED; Intermediate CA -> EE",
              "ISDOSC_D1.ors", "D1_Issuer_ICA.pem", "", 1, 1);
    test_ocsp("DELEGATED; Root CA -> Intermediate CA",
              "ISDOSC_D2.ors", "D2_Issuer_Root.pem", "", 1, 1);
    test_ocsp("DELEGATED; Root CA -> EE",
              "ISDOSC_D3.ors", "D3_Issuer_Root.pem", "", 1, 1);
};

subtest "=== WRONG SUBJECT NAME in the ISSUER CERTIFICATE ===" => sub {
    plan tests => 6;

    test_ocsp("NON-DELEGATED; Intermediate CA -> EE",
              "ND1.ors", "WSNIC_ND1_Issuer_ICA.pem", "", 1, 0);
    test_ocsp("NON-DELEGATED; Root CA -> Intermediate CA",
              "ND2.ors", "WSNIC_ND2_Issuer_Root.pem", "", 1, 0);
    test_ocsp("NON-DELEGATED; Root CA -> EE",
              "ND3.ors", "WSNIC_ND3_Issuer_Root.pem", "", 1, 0);
    test_ocsp("DELEGATED; Intermediate CA -> EE",
              "D1.ors", "WSNIC_D1_Issuer_ICA.pem", "", 1, 0);
    test_ocsp("DELEGATED; Root CA -> Intermediate CA",
              "D2.ors", "WSNIC_D2_Issuer_Root.pem", "", 1, 0);
    test_ocsp("DELEGATED; Root CA -> EE",
              "D3.ors", "WSNIC_D3_Issuer_Root.pem", "", 1, 0);
};

subtest "=== WRONG KEY in the ISSUER CERTIFICATE ===" => sub {
    plan tests => 6;

    test_ocsp("NON-DELEGATED; Intermediate CA -> EE",
              "ND1.ors", "WKIC_ND1_Issuer_ICA.pem", "", 1, 0);
    test_ocsp("NON-DELEGATED; Root CA -> Intermediate CA",
              "ND2.ors", "WKIC_ND2_Issuer_Root.pem", "", 1, 0);
    test_ocsp("NON-DELEGATED; Root CA -> EE",
              "ND3.ors", "WKIC_ND3_Issuer_Root.pem", "", 1, 0);
    test_ocsp("DELEGATED; Intermediate CA -> EE",
              "D1.ors", "WKIC_D1_Issuer_ICA.pem", "", 1, 0);
    test_ocsp("DELEGATED; Root CA -> Intermediate CA",
              "D2.ors", "WKIC_D2_Issuer_Root.pem", "", 1, 0);
    test_ocsp("DELEGATED; Root CA -> EE",
              "D3.ors", "WKIC_D3_Issuer_Root.pem", "", 1, 0);
};

subtest "=== INVALID SIGNATURE on the ISSUER CERTIFICATE ===" => sub {
    plan tests => 6;

    # Expect success, because we're explicitly trusting the issuer certificate.
    test_ocsp("NON-DELEGATED; Intermediate CA -> EE",
              "ND1.ors", "ISIC_ND1_Issuer_ICA.pem", "", 0, 0);
    test_ocsp("NON-DELEGATED; Root CA -> Intermediate CA",
              "ND2.ors", "ISIC_ND2_Issuer_Root.pem", "", 0, 0);
    test_ocsp("NON-DELEGATED; Root CA -> EE",
              "ND3.ors", "ISIC_ND3_Issuer_Root.pem", "", 0, 0);
    test_ocsp("DELEGATED; Intermediate CA -> EE",
              "D1.ors", "ISIC_D1_Issuer_ICA.pem", "", 0, 0);
    test_ocsp("DELEGATED; Root CA -> Intermediate CA",
              "D2.ors", "ISIC_D2_Issuer_Root.pem", "", 0, 0);
    test_ocsp("DELEGATED; Root CA -> EE",
              "D3.ors", "ISIC_D3_Issuer_Root.pem", "", 0, 0);
};

my $cert = data_file("cert.pem");
my $key = data_file("key.pem");
subtest "=== OCSP API TESTS===" => sub {
    plan tests => 1;

    ok(run(test(["ocspapitest", $cert, $key])),
                 "running ocspapitest");
};

subtest "=== OCSP VERIFICATION TESTS ===" => sub {
    plan tests => 1;

    ok(run(test(["ocsptest"])), "running ocsptest");
};

subtest "=== UNTRUSTED ISSUER HINTS ===" => sub {
    plan tests => 1;

    test_ocsp("NON-DELEGATED; invalid issuer via -issuer",
              "ND1.ors", "ND1_Cross_Root.pem",
              "ISIC_ND1_Issuer_ICA.pem", 1, 0, "-issuer");
};

subtest "=== OCSP handling of identical input and output files ===" => sub {
    plan tests => 5;

    my $inout1 = "req.der";
    my $backup1 = "backup.der";
    ok(run(app(['openssl', 'ocsp', '-issuer', $cert, '-cert', $cert,
                '-reqout', $inout1])), "produce dummy request input");
    copy($inout1, $backup1);
    ok(run(app(['openssl', 'ocsp', '-reqin', $inout1, '-reqout', $inout1])));
    ok(!compare($inout1, $backup1), "copied request $inout1 did not change");

    my $inout2 = "ND1.dat";
    my $backup2 = "backup.dat";
    copy($inout2, $backup2);
    ok(run(app(['openssl', 'ocsp', '-respin', $inout2, '-respout', $inout2, '-noverify'])));
    ok(!compare($inout2, $backup2), "copied response $inout2 did not change");
};

subtest "=== OCSP offline request/responder/verify round-trip ===" => sub {
    plan tests => 6;

    # Offline round-trip: build a request, answer it with the built-in
    # responder using a static index, then verify the response.
    my $issuer = catfile($ocspdir, "intermediate-cert.pem");
    my $ee     = catfile($ocspdir, "server-cert.pem");
    my $index  = catfile($ocspdir, "index.txt");
    my $rsigner = catfile($ocspdir, "ocsp.pem");
    my $root   = catfile($ocspdir, "root-cert.pem");

    # The serial of server-cert.pem is listed as valid in index.txt, so its
    # status is "good"; a serial absent from the index yields "unknown".
    my $roundtrip = sub {
        my ($title, $reqargs, $status) = @_;
        my $req = "rt-req.der";
        my $resp = "rt-resp.der";

        ok(run(app(['openssl', 'ocsp', '-issuer', $issuer, @$reqargs,
                    '-reqout', $req])),
           "$title: produce request");
        ok(run(app(['openssl', 'ocsp', '-index', $index, '-rsigner', $rsigner,
                    '-CA', $issuer, '-reqin', $req, '-respout', $resp])),
           "$title: responder produces response");
        # Passing the request again lets print_ocsp_summary report the status.
        ok(run(app(['openssl', 'ocsp', '-issuer', $issuer, @$reqargs,
                    '-no_nonce', '-respin', $resp, '-CAfile', $root,
                    '-verify_other', $rsigner,
                    '-no-CApath', '-no-CAstore'])),
           "$title: verify self-generated response ($status)");
    };

  SKIP: {
        # The responder certificates use EC keys.
        skip "EC is not supported by this OpenSSL build", 6 if disabled("ec");

        $roundtrip->("GOOD (by cert)", ['-cert', $ee], "good");
        $roundtrip->("UNKNOWN (by serial)", ['-serial', '0x1234'], "unknown");
    }
};

# Minimal DER helpers for building OCSP requests with crafted nonces.
sub der_tlv {
    my ($tag, $content) = @_;
    my $len = length($content);
    my $lenbytes;

    if ($len < 0x80) {
        $lenbytes = chr($len);
    } else {
        my $l = "";
        while ($len > 0) {
            $l = chr($len & 0xff) . $l;
            $len >>= 8;
        }
        $lenbytes = chr(0x80 | length($l)) . $l;
    }
    return chr($tag) . $lenbytes . $content;
}

# Return the content of the DER TLV at the start of $der.
sub der_content {
    my ($der) = @_;
    my $len = ord(substr($der, 1, 1));
    my $hdr = 2;

    if ($len & 0x80) {
        my $n = $len & 0x7f;
        $len = 0;
        $len = ($len << 8) | ord(substr($der, 2 + $_, 1)) for 0 .. $n - 1;
        $hdr += $n;
    }
    return substr($der, $hdr, $len);
}

subtest "=== OCSP responder nonce validation (RFC 9654) ===" => sub {
    my $issuer  = catfile($ocspdir, "intermediate-cert.pem");
    my $ee      = catfile($ocspdir, "server-cert.pem");
    my $index   = catfile($ocspdir, "index.txt");
    my $rsigner = catfile($ocspdir, "ocsp.pem");
    my $root    = catfile($ocspdir, "root-cert.pem");

    # id-pkix-ocsp-nonce, 1.3.6.1.5.5.7.48.1.2
    my $nonce_oid = der_tlv(0x06, "\x2b\x06\x01\x05\x05\x07\x30\x01\x02");
    my $octets = sub { der_tlv(0x04, "\x5a" x shift) };
    my %statuses = (successful => 0, malformedRequest => 1);

    # Each case lists the extnValue of every nonce extension in the request
    # and the expected responseStatus.
    my @cases = (
        [ "1-octet nonce",   [ $octets->(1) ],   "successful" ],
        [ "32-octet nonce",  [ $octets->(32) ],  "successful" ],
        [ "128-octet nonce", [ $octets->(128) ], "successful" ],
        [ "empty nonce",     [ $octets->(0) ],   "malformedRequest" ],
        [ "129-octet nonce", [ $octets->(129) ], "malformedRequest" ],
        [ "nonce that is not an OCTET STRING",
          [ der_tlv(0x02, "\x01") ], "malformedRequest" ],
        [ "trailing data after the nonce",
          [ $octets->(32) . ("\0" x 16) ], "malformedRequest" ],
        [ "nonce with a non-minimal length encoding",
          [ "\x04\x81\x20" . ("\x5a" x 32) ], "malformedRequest" ],
        [ "nonce with an indefinite length",
          [ "\x04\x80" . ("\x5a" x 32) . "\0\0" ], "malformedRequest" ],
        [ "constructed (BER) nonce",
          [ der_tlv(0x24, $octets->(1) . ($octets->(0) x 4)) ],
          "malformedRequest" ],
        [ "valid nonce followed by an empty one",
          [ $octets->(32), $octets->(0) ], "malformedRequest" ],
        [ "empty nonce followed by a valid one",
          [ $octets->(0), $octets->(32) ], "malformedRequest" ],
        [ "two valid nonces",
          [ $octets->(32), $octets->(32) ], "malformedRequest" ],
    );

    plan skip_all => "EC is not supported by this OpenSSL build"
        if disabled("ec");
    plan tests => 3 + 3 * scalar(@cases);

    # A request made with the default client options must carry a nonce of
    # 32 octets: extnValue ::= OCTET STRING { OCTET STRING (32 octets) }
    my $defreq = "nonce-default-req.der";
    ok(run(app(['openssl', 'ocsp', '-issuer', $issuer, '-cert', $ee,
                '-reqout', $defreq])),
       "produce request with the default nonce");
    open(my $fh, "<", $defreq) or die "Cannot open $defreq: $!";
    binmode $fh;
    my $defbytes = do { local $/; <$fh> };
    close $fh;
    ok(index($defbytes, $nonce_oid . "\x04\x22\x04\x20") >= 0,
       "client request contains a 32-octet nonce");

    my $base = "nonce-base.der";
    ok(run(app(['openssl', 'ocsp', '-issuer', $issuer, '-cert', $ee,
                '-no_nonce', '-reqout', $base])),
       "produce request without a nonce");

    open($fh, "<", $base) or die "Cannot open $base: $!";
    binmode $fh;
    my $basereq = do { local $/; <$fh> };
    close $fh;
    # OCSPRequest ::= SEQUENCE { tbsRequest, ... }
    my $tbs = der_content(der_content($basereq));

    foreach my $case (@cases) {
        my ($title, $values, $status) = @$case;
        my $exts = join("", map {
            der_tlv(0x30, $nonce_oid . der_tlv(0x04, $_))
        } @$values);
        # requestExtensions [2] EXPLICIT Extensions
        my $req = der_tlv(0x30, der_tlv(0x30, $tbs
                                        . der_tlv(0xa2, der_tlv(0x30, $exts))));
        my $reqfile = "nonce-req.der";
        my $respfile = "nonce-resp.der";

        open($fh, ">", $reqfile) or die "Cannot open $reqfile: $!";
        binmode $fh;
        print $fh $req;
        close $fh;

        unlink $respfile;
        my $exit = $status eq "successful" ? 0 : 1;
        with({ exit_checker => sub { return shift == $exit; } },
             sub {
                 ok(run(app(['openssl', 'ocsp', '-index', $index,
                             '-rsigner', $rsigner, '-CA', $issuer,
                             '-reqin', $reqfile, '-respout', $respfile])),
                    "$title: responder produces response");
             });

        # OCSPResponse ::= SEQUENCE {
        #     responseStatus  ENUMERATED,
        #     responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL }
        open($fh, "<", $respfile) or die "Cannot open $respfile: $!";
        binmode $fh;
        my $resp = der_content(do { local $/; <$fh> });
        close $fh;
        is(unpack("H*", substr($resp, 0, 3)),
           sprintf("0a01%02x", $statuses{$status}),
           "$title: responseStatus is $status");
        if ($status eq "successful") {
            # Verifying against the request also checks that the nonce in the
            # response is the one from the request (no -noverify here)
            ok(run(app(['openssl', 'ocsp', '-reqin', $reqfile,
                        '-respin', $respfile, '-CAfile', $root,
                        '-verify_other', $rsigner,
                        '-no-CApath', '-no-CAstore'])),
               "$title: response verifies against the request, nonce echoed");
        } else {
            is(length($resp), 3, "$title: no responseBytes");
        }
    }
};
