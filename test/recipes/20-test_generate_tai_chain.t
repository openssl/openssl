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
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_generate_tai_chain");

plan tests => 9;

my $cert = srctop_file("test", "certs", "ca-cert.pem");
my $out = "tai-chain.pem";

# Read the PEM contents of a named block from a file, decoded to raw bytes.
sub read_pem_block {
    my ($file, $name) = @_;
    open(my $fh, "<", $file) or return undef;
    my ($in, $b64) = (0, "");
    while (my $line = <$fh>) {
        if ($line =~ /^-----BEGIN \Q$name\E-----/) { $in = 1; next; }
        if ($line =~ /^-----END \Q$name\E-----/) { last; }
        $b64 .= $line if $in;
    }
    close($fh);
    return $in ? decode_base64($b64) : undef;
}

# Decorate a single certificate with a trust_anchor_id.
ok(run(app(["openssl", "generate_tai_chain",
            "-chain", $cert, "-oid", "32473.1", "-out", $out])),
   "decorate a certificate with a trust anchor ID");

# The output carries a CERTIFICATE PROPERTIES block ...
my $props = read_pem_block($out, "CERTIFICATE PROPERTIES");
ok(defined $props, "output has a CERTIFICATE PROPERTIES block");

# ... whose CertificatePropertyList is exactly one trust_anchor_id property
# holding the relative OID content octets for 32473.1 (81 fd 59 01).
is(defined $props ? unpack("H*", $props) : "",
   "00080000000481fd5901",
   "properties encode the expected trust_anchor_id");

# The certificate itself is still present.
ok(defined read_pem_block($out, "CERTIFICATE"),
   "output still has the certificate");

# Re-decorating a file that already has properties must fail.
ok(!run(app(["openssl", "generate_tai_chain",
             "-chain", $out, "-oid", "32473.1"])),
   "refuse a chain that already has a CERTIFICATE PROPERTIES block");

# -oid is required.
ok(!run(app(["openssl", "generate_tai_chain", "-chain", $cert])),
   "fail without -oid");

# A malformed group pattern is rejected.
ok(!run(app(["openssl", "generate_tai_chain",
             "-chain", $cert, "-oid", "32473.1",
             "-group", "2187.{notanumber-200}"])),
   "reject a malformed group pattern");

# Group patterns and trust_anchor_negotiation follow the trust_anchor_id.
ok(run(app(["openssl", "generate_tai_chain",
            "-chain", $cert, "-oid", "32473.1", "-out", $out,
            "-group", "32473.1.2.{0-}.{0-},32473.{123-456}.{789-}",
            "-trust-anchor-negotiation"])),
   "decorate a certificate with group patterns");
$props = read_pem_block($out, "CERTIFICATE PROPERTIES");
is(defined $props ? unpack("H*", $props) : "",
   "002e0000000481fd59010001001e001c0e81fd5981fd590101020200800080"
   . "0c81fd5981fd597b834886158000020000",
   "properties encode the expected trust_anchor_groups");
