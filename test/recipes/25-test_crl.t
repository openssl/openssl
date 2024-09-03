#! /usr/bin/env perl
# Copyright 2015-2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT srctop_file data_file/;

setup("test_crl");

plan tests => 8;

require_ok(srctop_file('test', 'recipes', 'tconversion.pl'));

my $pem = srctop_file('test/certs', 'cyrillic_crl.pem');
my $out = 'cyrillic_crl.out';
my $utf8 = srctop_file("test/certs", "cyrillic_crl.utf8");
my $test_crl = srctop_file('test', 'testcrl.pem');

subtest 'CRL conversions' => sub {
    tconversion(-type => 'crl', -in => srctop_file('test', 'testcrl.pem'));
};

ok(run(test(['crltest'])));

# Fingerprint tests
subtest 'Fingerprint verification' => sub {
    check_fingerprint(
        [qw{openssl crl -noout -fingerprint -in}, $test_crl],
        'SHA1 Fingerprint=BA:F4:1B:AD:7A:9B:2F:09:16:BC:60:A7:0E:CE:79:2E:36:00:E7:B2',
        'SHA1 fingerprint verification'
    );
    check_fingerprint(
        [qw{openssl crl -noout -fingerprint -sha256 -in}, $test_crl],
        'SHA2-256 Fingerprint=B3:A9:FD:A7:2E:8C:3D:DF:D0:F1:C3:1A:96:60:B5:FD:B0:99:7C:7F:0E:E4:34:F5:DB:87:62:36:BC:F1:BC:1B',
        'SHA256 fingerprint verification'
    );
    check_fingerprint(
        [qw{openssl crl -noout -hash -in}, $test_crl],
        '106cd822',
        'CRL hash verification'
    );
    check_fingerprint(
        [qw{openssl crl -noout -hash}],
        '106cd822',
        "crl piped input test",
        $test_crl,
    );
};


# CRL PEM and UTF8 conversion tests
ok(!run(app(["openssl", "crl", "-text", "-in", $pem, "-inform", "DER",
             "-out", $out, "-nameopt", "utf8"])));
ok(run(app(["openssl", "crl", "-text", "-in", $pem, "-inform", "PEM",
            "-out", $out, "-nameopt", "utf8"])));
is(cmp_text($out, $utf8), 0, 'Comparing utf8 output');

# Test whether the order of CA certificates affects CRL verification.
# The CRL `crl_for_ca1.pem` is issued by CA1, but all four CA certificates
# (CA1, CA2, CA3, and CA4) share the same subject name but use different keys.
# This setup is unusual and tests a specific edge case where multiple CAs have
# identical subject names but distinct cryptographic identities.
#
# The verification should succeed with any CA file that includes the CA1
# certificate, regardless of the order in which the CAs appear in the bundle.
# The test ensures that the verification process correctly identifies and uses
# the right CA (CA1) based on its key, not just its subject name, demonstrating
# the robustness of the CRL verification mechanism.
my @valid_ca_bundles = qw(
    ca1_cert.pem ca12_bundle.pem ca21_bundle.pem
    ca123_bundle.pem ca321_bundle.pem ca412_bundle.pem
);
my @invalid_ca_bundles = qw(
    ca2_cert.pem ca3_cert.pem ca4_cert.pem
    ca43_bundle.pem ca234_bundle.pem ca432_bundle.pem
);
my $crl_path = data_file("crl_for_ca1.pem");

# Test CA bundles
subtest 'CA bundle order tests' => sub {
    test_ca_bundles(\@valid_ca_bundles, 1, 'Valid', $crl_path);
    test_ca_bundles(\@invalid_ca_bundles, 0, 'Invalid', $crl_path);
};

done_testing();

sub check_fingerprint {
    my ($cmd, $expected, $test_name, $infile) = @_;
    ok(compare_first_line($cmd, $expected, $infile), $test_name);
}

sub compare_first_line {
    my ($cmd_array, $str, $infile) = @_;
    my %app_param = ();

    $app_param{stdin} = $infile if defined $infile;
    my @lines = run(app($cmd_array, %app_param), capture => 1);
    return 1 if $lines[0] =~ m|^\Q${str}\E\R$|;
    note "Got      ", $lines[0];
    note "Expected ", $str;
    return 0;
}

sub test_ca_bundles {
    my ($bundles, $expected_result, $test_type, $crl) = @_;

    foreach my $ca_bundle (@$bundles) {
        my $ca_bundle_path = data_file($ca_bundle);
        my $result = run(app(["openssl", "crl", "-in", $crl, "-CAfile",
                              $ca_bundle_path, "-noout"]));
        if ($result != $expected_result) {
            note "Verified CRL with bundle:", $ca_bundle;
            note "Got: ", $result;
            note "Expected $test_type: ", $expected_result;
        }
        ok($result == $expected_result,
           "$test_type CA bundle test for $ca_bundle_path");
    }
}
