#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# Test for RFC 5280 compliance: NameConstraints with non-contiguous subnet masks
# This combines C API tests and CLI-based certificate creation/verification tests
#

use strict;
use warnings;

use File::Spec;
use File::Temp qw(tempdir);
use OpenSSL::Test qw/:DEFAULT srctop_file bldtop_dir data_file/;
use OpenSSL::Test::Utils;

setup("test_verify_nc_invalid_mask");

plan tests => 17;

# =============================================================================
# Part 1: Run the C API test program (Test 1)
# =============================================================================

ok(run(test(['nc_invalid_mask_test'])),
   "Running C API tests for non-contiguous subnet masks");

# =============================================================================
# Part 2: CLI-based tests creating and verifying certificates (Tests 2-17)
# =============================================================================

# Create temporary directory for test certificates
my $tempdir = tempdir(CLEANUP => 1);

# Helper function to create a CA certificate with name constraints
sub create_nc_ca {
    my ($name, $nc_config) = @_;

    my $keyfile = File::Spec->catfile($tempdir, "$name-key.pem");
    my $certfile = File::Spec->catfile($tempdir, "$name-cert.pem");
    my $extfile = File::Spec->catfile($tempdir, "$name-ext.cnf");

    # Create extension config file
    open(my $fh, '>', $extfile) or die "Cannot create $extfile: $!";
    print $fh "[req]\n";
    print $fh "distinguished_name = req_distinguished_name\n\n";
    print $fh "[req_distinguished_name]\n\n";
    print $fh "[v3_ca]\n";
    print $fh "basicConstraints = critical,CA:TRUE\n";
    print $fh "keyUsage = keyCertSign,cRLSign\n";
    print $fh "subjectKeyIdentifier = hash\n";
    print $fh "authorityKeyIdentifier = keyid\n";
    print $fh "nameConstraints = $nc_config\n";
    close($fh);

    # Generate key
    ok(run(app(['openssl', 'genpkey',
                '-algorithm', 'RSA',
                '-pkeyopt', 'rsa_keygen_bits:2048',
                '-out', $keyfile])),
       "Generate key for $name");

    # Create self-signed CA certificate
    ok(run(app(['openssl', 'req', '-new', '-x509',
                '-key', $keyfile,
                '-out', $certfile,
                '-days', '3650',
                '-subj', "/CN=Test NC CA $name",
                '-extensions', 'v3_ca',
                '-config', $extfile])),
       "Create CA certificate for $name with nameConstraints=$nc_config");

    return ($keyfile, $certfile);
}

# Helper function to create an end-entity certificate
sub create_ee_cert {
    my ($name, $ca_key, $ca_cert, $san) = @_;

    my $keyfile = File::Spec->catfile($tempdir, "$name-key.pem");
    my $csrfile = File::Spec->catfile($tempdir, "$name.csr");
    my $certfile = File::Spec->catfile($tempdir, "$name-cert.pem");
    my $extfile = File::Spec->catfile($tempdir, "$name-ext.cnf");

    # Create extension config file
    open(my $fh, '>', $extfile) or die "Cannot create $extfile: $!";
    print $fh "basicConstraints = CA:FALSE\n";
    print $fh "subjectKeyIdentifier = hash\n";
    print $fh "authorityKeyIdentifier = keyid,issuer\n";
    print $fh "subjectAltName = $san\n" if $san;
    close($fh);

    # Generate key
    run(app(['openssl', 'genpkey',
             '-algorithm', 'RSA',
             '-pkeyopt', 'rsa_keygen_bits:2048',
             '-out', $keyfile]));

    # Create CSR
    run(app(['openssl', 'req', '-new',
             '-key', $keyfile,
             '-out', $csrfile,
             '-subj', "/CN=$name"]));

    # Sign certificate
    run(app(['openssl', 'x509', '-req',
             '-in', $csrfile,
             '-CA', $ca_cert,
             '-CAkey', $ca_key,
             '-CAcreateserial',
             '-out', $certfile,
             '-days', '365',
             '-extfile', $extfile]));

    return $certfile;
}

# Helper function to verify a certificate
sub verify_cert {
    my ($cert, $ca_cert) = @_;
    return run(app(['openssl', 'verify',
                    '-CAfile', $ca_cert,
                    $cert]));
}

# Tests 2-3: Create CA with invalid IPv4 mask 255.0.255.0
my ($ca1_key, $ca1_cert) = create_nc_ca('ca-invalid-ipv4-1',
                                         'permitted;IP:192.168.0.0/255.0.255.0');

# Create end-entity cert within the "permitted" range
my $ee1_permitted = create_ee_cert('ee1-permitted', $ca1_key, $ca1_cert,
                                    'IP:192.168.1.1');

# Test 4: Verify the certificate - this should ideally fail due to invalid mask,
# but currently passes (demonstrating the bug)
ok(!verify_cert($ee1_permitted, $ca1_cert),
   "CURRENT: Certificate with invalid CA mask 255.0.255.0 is accepted rejected");

# Tests 5-6: Create CA with invalid IPv4 mask 255.255.128.255
my ($ca2_key, $ca2_cert) = create_nc_ca('ca-invalid-ipv4-2',
                                         'excluded;IP:10.0.0.0/255.255.128.255');

# Create end-entity cert
my $ee2 = create_ee_cert('ee2', $ca2_key, $ca2_cert, 'IP:172.16.0.1');

# Test 7: Verify
ok(!verify_cert($ee2, $ca2_cert),
   "CURRENT: Certificate with invalid CA mask 255.255.128.255 is rejected");

# Tests 8-9: Create CA with invalid IPv4 mask 255.255.254.1
my ($ca3_key, $ca3_cert) = create_nc_ca('ca-invalid-ipv4-3',
                                         'permitted;IP:172.16.0.0/255.255.254.1');

# Create end-entity cert
my $ee3 = create_ee_cert('ee3', $ca3_key, $ca3_cert, 'IP:172.16.0.1');

# Test 10: Verify
ok(!verify_cert($ee3, $ca3_cert),
   "CURRENT: Certificate with invalid CA mask 255.255.254.1 is rejected");

# Tests 11-12: Create CA with VALID IPv4 mask (for comparison)
my ($ca_valid_key, $ca_valid_cert) = create_nc_ca('ca-valid-ipv4',
                                                    'permitted;IP:192.168.0.0/255.255.255.0');

# Create end-entity cert within permitted range
my $ee_valid = create_ee_cert('ee-valid', $ca_valid_key, $ca_valid_cert,
                               'IP:192.168.0.100');

# Test 13: Verify - this should pass
ok(verify_cert($ee_valid, $ca_valid_cert),
   "Certificate with valid CA mask 255.255.255.0 is accepted");

# Tests 14-15: Create CA with valid IPv4 /24 mask
my ($ca_cidr_key, $ca_cidr_cert) = create_nc_ca('ca-valid-cidr',
                                                 'permitted;IP:10.0.0.0/255.255.255.0');

# Create end-entity cert within permitted range
my $ee_cidr = create_ee_cert('ee-cidr', $ca_cidr_key, $ca_cidr_cert, 'IP:10.0.0.50');

# Test 16: Verify certificate within permitted range
ok(verify_cert($ee_cidr, $ca_cidr_cert),
   "Certificate with valid CIDR-style CA mask is accepted");

# Create end-entity cert outside permitted range
my $ee_outside = create_ee_cert('ee-outside', $ca_cidr_key, $ca_cidr_cert, 'IP:10.0.1.50');

# Test 17: Verify that IP outside permitted range is rejected
ok(!verify_cert($ee_outside, $ca_cidr_cert),
   "Certificate with IP outside permitted range is rejected");
