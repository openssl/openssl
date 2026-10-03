#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Copy qw(copy);
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_nseq");

plan tests => 5;

my $cert = srctop_file("test", "certs", "ca-cert.pem");
my $valid_sequence = "nseq-valid.seq";
my $malformed_input = "nseq-malformed.pem";
my $malformed_sequence = "nseq-malformed.seq";
my $malformed_stderr = "nseq-malformed.err";

ok(run(app(["openssl", "nseq", "-toseq", "-in", $cert,
            "-out", $valid_sequence])),
   "convert a valid certificate to a sequence");
ok(run(app(["openssl", "nseq", "-in", $valid_sequence,
            "-out", "nseq-valid.pem"])),
   "read the generated certificate sequence");

ok(copy($cert, $malformed_input), "copy the valid certificate");
open my $fh, ">>", $malformed_input
    or die "Could not open $malformed_input: $!";
print $fh <<'EOF';
-----BEGIN CERTIFICATE-----
not a valid base64 encoded certificate
-----END CERTIFICATE-----
EOF
close $fh or die "Could not close $malformed_input: $!";

ok(!run(app(["openssl", "nseq", "-toseq", "-in", $malformed_input,
             "-out", $malformed_sequence],
            stderr => $malformed_stderr)),
   "reject a malformed trailing certificate");
open my $errfh, "<", $malformed_stderr
    or die "Could not open $malformed_stderr: $!";
my $stderr = do { local $/; <$errfh> };
close $errfh;
like($stderr, qr/PEM routines/, "report the PEM parsing error");
