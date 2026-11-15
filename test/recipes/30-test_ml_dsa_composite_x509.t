#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use MIME::Base64;
use OpenSSL::Test qw(:DEFAULT srctop_file);
use OpenSSL::Test::Utils;

setup("test_ml_dsa_composite_x509");

plan skip_all => 'ML DSA Composite signatures are not supported in this build'
    if disabled('ml-dsa-composite');

my $no_ec = disabled('ec');

my @algs = (
    "ML-DSA-44-RSA2048-PSS-SHA256",
    "ML-DSA-44-ECDSA-P256-SHA256",
    "ML-DSA-87-ECDSA-P384-SHA512",
    "ML-DSA-87-RSA4096-PSS-SHA512",
);
@algs = grep { $_ !~ /ECDSA/ } @algs if $no_ec;

# Per algorithm: CSR (create, verify, 2 tampered), certificate (create,
# signature algorithm name, verify, 2 tampered)
plan tests => 9 * @algs;

# Return the content offset and length of the DER element starting at $pos
sub der_content {
    my ($der, $pos) = @_;
    my $len = ord(substr($der, $pos + 1, 1));
    my $start = $pos + 2;

    if ($len & 0x80) {
        my $n = $len & 0x7f;
        $len = 0;
        $len = ($len << 8) | ord(substr($der, $start++, 1)) for 1 .. $n;
    }
    return ($start, $len);
}

# Copy the PEM $in (a CSR or certificate, which both end in a signature BIT
# STRING) to $out with one bit of the signature flipped.  The composite
# signature is mldsaSig || tradSig, so "first" damages the ML-DSA component
# and "last" the traditional one.
sub tamper_signature {
    my ($in, $out, $label, $where) = @_;

    open(my $fh, '<', $in) or die "cannot read $in: $!";
    my $pem = do { local $/; <$fh> };
    close($fh);
    $pem =~ /-----BEGIN \Q$label\E-----(.*?)-----END/s
        or die "no $label in $in";
    my $der = decode_base64($1);

    # { tbs, signatureAlgorithm, signatureValue }: step to the third element
    my ($pos) = der_content($der, 0);
    for (1 .. 2) {
        my ($start, $len) = der_content($der, $pos);
        $pos = $start + $len;
    }
    my ($start, $len) = der_content($der, $pos);

    # the first content byte of a BIT STRING counts its unused bits
    my $idx = $where eq "first" ? $start + 1 : $start + $len - 1;
    substr($der, $idx, 1) = chr(ord(substr($der, $idx, 1)) ^ 0x01);

    open($fh, '>', $out) or die "cannot write $out: $!";
    print $fh "-----BEGIN $label-----\n", encode_base64($der, "\n"),
        "-----END $label-----\n";
    close($fh);
}

foreach my $alg (@algs) {
    my $base = lc($alg);
    my $key = "$base-key.pem";
    my $csr = "$base-csr.pem";
    my $cert = "$base-cert.pem";

    ok(run(app(["openssl", "req", "-new",
                "-config", srctop_file("test", "test.cnf"),
                "-newkey", $alg, "-nodes", "-keyout", $key,
                "-subj", "/CN=composite-csr", "-out", $csr])),
       "create a certificate request: $alg");

    ok(run(app(["openssl", "req", "-verify", "-noout", "-in", $csr])),
       "verify the certificate request signature: $alg");

    foreach my $where ("first", "last") {
        my $bad = "$base-csr-bad-$where.pem";

        tamper_signature($csr, $bad, "CERTIFICATE REQUEST", $where);
        ok(!run(app(["openssl", "req", "-verify", "-noout", "-in", $bad])),
           "reject a request with a damaged $where signature byte: $alg");
    }

    ok(run(app(["openssl", "req", "-x509", "-days", "365",
                "-config", srctop_file("test", "test.cnf"),
                "-newkey", $alg, "-nodes", "-keyout", $key,
                "-subj", "/CN=composite-cert",
                "-addext", "keyUsage=digitalSignature", "-out", $cert])),
       "create a self-signed certificate: $alg");

    my $text = "$base-cert.txt";
    ok(run(app(["openssl", "x509", "-in", $cert, "-noout", "-text",
                "-out", $text]))
       && do {
           open(my $fh, '<', $text) or die "cannot read $text: $!";
           my $found = grep { /^\s*Signature Algorithm: \Q$alg\E$/ } <$fh>;
           close($fh);
           $found;
       },
       "the certificate is signed with the composite algorithm: $alg");

    ok(run(app(["openssl", "verify", "-check_ss_sig", "-CAfile", $cert, $cert])),
       "verify the self-signed certificate: $alg");

    foreach my $where ("first", "last") {
        my $bad = "$base-cert-bad-$where.pem";

        tamper_signature($cert, $bad, "CERTIFICATE", $where);
        ok(!run(app(["openssl", "verify", "-check_ss_sig",
                     "-CAfile", $bad, $bad])),
           "reject a certificate with a damaged $where signature byte: $alg");
    }
}
