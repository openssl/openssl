#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_x509");

plan tests => 10;

require_ok(srctop_file('test','recipes','tconversion.pl'));

my $pem = srctop_file("test/certs", "cyrillic.pem");
my $out = "cyrillic.out";
my $msb = srctop_file("test/certs", "cyrillic.msb");
my $utf = srctop_file("test/certs", "cyrillic.utf8");

ok(run(app(["openssl", "x509", "-text", "-in", $pem, "-out", $out,
            "-nameopt", "esc_msb"])));
is(cmp_text($out, srctop_file("test/certs", "cyrillic.msb")),
   0, 'Comparing esc_msb output');
ok(run(app(["openssl", "x509", "-text", "-in", $pem, "-out", $out,
            "-nameopt", "utf8"])));
is(cmp_text($out, srctop_file("test/certs", "cyrillic.utf8")),
   0, 'Comparing utf8 output');
unlink $out;

SKIP: {
    skip "EC disabled", 1 if disabled("ec");

    # producing and checking self-issued (but not self-signed) cert
    my @path = qw(test certs);
    my $subj = "/CN=CA"; # using same DN as in issuer of ee-cert.pem
    my $pkey = srctop_file(@path, "ca-key.pem"); #  issuer private key
    my $pubkey = "ca-pubkey.pem"; # the corresponding issuer public key
    # use any (different) key for signing our self-issued cert:
    my $signkey = srctop_file(@path, "ee-ecdsa-key.pem");
    my $selfout = "self-issued.out";
    my $testcert = srctop_file(@path, "ee-cert.pem");
    ok(run(app(["openssl", "pkey", "-in", $pkey, "-pubout", "-out", $pubkey]))
       &&
       run(app(["openssl", "x509", "-new", "-force_pubkey", $pubkey,
                "-subj", $subj, "-signkey", $signkey, "-out", $selfout]))
       &&
       run(app(["openssl", "verify", "-no_check_time",
                "-trusted", $selfout, $testcert])));
    unlink $pubkey;
    unlink $selfout;
}

subtest 'x509 -- x.509 v1 certificate' => sub {
    tconversion("x509", srctop_file("test","testx509.pem"));
};
subtest 'x509 -- first x.509 v3 certificate' => sub {
    tconversion("x509", srctop_file("test","v3-cert1.pem"));
};
subtest 'x509 -- second x.509 v3 certificate' => sub {
    tconversion("x509", srctop_file("test","v3-cert2.pem"));
};

subtest 'x509 -- pathlen' => sub {
    ok(run(test(["v3ext", srctop_file("test/certs", "pathlen.pem")])));
}
