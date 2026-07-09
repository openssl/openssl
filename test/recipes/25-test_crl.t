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
use File::Copy;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_crl");

plan tests => 12;

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

# Verify a CRL's signature against its issuer certificate, supplied via
# -CAfile, -CAstore and -CApath.
subtest 'crl signature verification' => sub {
    plan tests => 4;

    my $crl = srctop_file("test/certs", "delta-crl-as-complete-delta.pem");
    my $cacert = srctop_file("test/certs", "delta-crl-as-complete-ca.pem");

    ok(run(app(["openssl", "crl", "-noout", "-in", $crl,
                "-CAfile", $cacert])),
       "verify CRL signature with -CAfile");

    ok(run(app(["openssl", "crl", "-noout", "-in", $crl,
                "-CAstore", $cacert])),
       "verify CRL signature with -CAstore");

    # -CApath needs a rehashed directory, which relies on the rehash command
    # (not available on platforms without symlink support, e.g. Windows).
    SKIP: {
        skip "rehash is not available on this platform", 2
            unless run(app(["openssl", "rehash", "-help"]));

        my $capath = "crl_capath";
        mkdir $capath;
        copy($cacert, File::Spec->catfile($capath, "ca.pem"));
        ok(run(app(["openssl", "rehash", $capath])),
           "rehash the -CApath directory");
        ok(run(app(["openssl", "crl", "-noout", "-in", $crl,
                    "-CApath", $capath])),
           "verify CRL signature with -CApath");
    }
};

# Cover -gendelta (delta CRL generation), which is the only code path in the
# crl app using the -key and -keyform options.
subtest 'crl delta generation with -gendelta, -key and -keyform' => sub {
    plan tests => 5;

    # copy the CA cert and key in locally so the config uses plain paths
    my $cacert = "gendelta-ca-cert.pem";
    my $cakey = "gendelta-ca-key.pem";
    copy(srctop_file("test", "certs", "ca-cert.pem"), $cacert);
    copy(srctop_file("test", "certs", "ca-key.pem"), $cakey);

    open my $cfg, '>', "gencrl.cnf" or die "Could not create gencrl.cnf: $!";
    print $cfg <<"EOF";
[ca]
default_ca = CA_default
[CA_default]
database = index.txt
certificate = $cacert
private_key = $cakey
crlnumber = crlnumber
default_md = sha256
default_crl_days = 30
EOF
    close $cfg;
    open my $db, '>', "index.txt" or die "Could not create index.txt: $!";
    close $db; # empty CA database
    open my $num, '>', "crlnumber" or die "Could not create crlnumber: $!";
    print $num "1000\n";
    close $num;

    run(app(["openssl", "ca", "-gencrl", "-config", "gencrl.cnf",
             "-out", "delta-base.crl"]));
    run(app(["openssl", "ca", "-gencrl", "-config", "gencrl.cnf",
             "-out", "delta-newer.crl"]));

    # -gendelta with a PEM signing key (the default -keyform)
    ok(run(app(["openssl", "crl", "-in", "delta-base.crl",
                "-gendelta", "delta-newer.crl",
                "-key", $cakey, "-out", "delta.crl"])),
       "generate delta CRL with -gendelta and a PEM -key");

    run(app(["openssl", "crl", "-in", "delta.crl", "-noout", "-text",
             "-out", "delta.txt"]));
    test_file_contains("delta CRL", "delta.txt", "Delta CRL Indicator", 1);

    # The same, loading the signing key from DER via -keyform DER
    run(app(["openssl", "pkey", "-in", $cakey, "-outform", "DER",
             "-out", "ca-key.der"]));
    ok(run(app(["openssl", "crl", "-in", "delta-base.crl",
                "-gendelta", "delta-newer.crl",
                "-key", "ca-key.der", "-keyform", "DER",
                "-out", "delta-der.crl"])),
       "generate delta CRL with a DER -key and -keyform DER");

    # -keyform must match the key encoding: a DER key read as PEM fails.
    ok(!run(app(["openssl", "crl", "-in", "delta-base.crl",
                 "-gendelta", "delta-newer.crl",
                 "-key", "ca-key.der", "-keyform", "PEM",
                 "-out", "delta-bad.crl"])),
       "wrong -keyform for the signing key makes -gendelta fail");

    # -gendelta requires a signing key.
    ok(!run(app(["openssl", "crl", "-in", "delta-base.crl",
                 "-gendelta", "delta-newer.crl", "-out", "delta-nokey.crl"])),
       "-gendelta without -key fails");
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
