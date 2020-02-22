#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use POSIX;
use File::Spec::Functions qw/catfile/;
use File::Compare qw/compare_text/;
use OpenSSL::Test qw/:DEFAULT srctop_dir srctop_file/;
use OpenSSL::Test::Utils;

setup("test_cms");

plan skip_all => "CMS is not supported by this OpenSSL build"
    if disabled("cms");

my $datadir = srctop_dir("test", "recipes", "80-test_cms_data");
my $smdir    = srctop_dir("test", "smime-certs");
my $smcont   = srctop_file("test", "smcont.txt");
my ($no_des, $no_dh, $no_dsa, $no_ec, $no_ec2m, $no_rc2, $no_zlib)
    = disabled qw/des dh dsa ec ec2m rc2 zlib/;

plan tests => 7;

my @smime_pkcs7_tests = (

    [ "signed content DER format, RSA key",
      [ "{cmd1}", "-sign", "-in", $smcont, "-outform", "DER", "-nodetach",
        "-certfile", catfile($smdir, "smroot.pem"),
        "-signer", catfile($smdir, "smrsa1.pem"), "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms", "-inform", "DER",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "signed detached content DER format, RSA key",
      [ "{cmd1}", "-sign", "-in", $smcont, "-outform", "DER",
        "-signer", catfile($smdir, "smrsa1.pem"), "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms", "-inform", "DER",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt",
        "-content", $smcont ],
      \&final_compare
    ],

    [ "signed content test streaming BER format, RSA",
      [ "{cmd1}", "-sign", "-in", $smcont, "-outform", "DER", "-nodetach",
        "-stream",
        "-signer", catfile($smdir, "smrsa1.pem"), "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms", "-inform", "DER",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "signed content DER format, DSA key",
      [ "{cmd1}", "-sign", "-in", $smcont, "-outform", "DER", "-nodetach",
        "-signer", catfile($smdir, "smdsa1.pem"), "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms", "-inform", "DER",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "signed detached content DER format, DSA key",
      [ "{cmd1}", "-sign", "-in", $smcont, "-outform", "DER",
        "-signer", catfile($smdir, "smdsa1.pem"), "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms", "-inform", "DER",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt",
        "-content", $smcont ],
      \&final_compare
    ],

    [ "signed detached content DER format, add RSA signer (with DSA existing)",
      [ "{cmd1}", "-sign", "-in", $smcont, "-outform", "DER",
        "-signer", catfile($smdir, "smdsa1.pem"), "-out", "{output}.cms" ],
      [ "{cmd1}", "-resign", "-in", "{output}.cms", "-inform", "DER", "-outform", "DER",
        "-signer", catfile($smdir, "smrsa1.pem"), "-out", "{output}2.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}2.cms", "-inform", "DER",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt",
        "-content", $smcont ],
      \&final_compare
    ],

    [ "signed content test streaming BER format, DSA key",
      [ "{cmd1}", "-sign", "-in", $smcont, "-outform", "DER",
        "-nodetach", "-stream",
        "-signer", catfile($smdir, "smdsa1.pem"), "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms", "-inform", "DER",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "signed content test streaming BER format, 2 DSA and 2 RSA keys",
      [ "{cmd1}", "-sign", "-in", $smcont, "-outform", "DER",
        "-nodetach", "-stream",
        "-signer", catfile($smdir, "smrsa1.pem"),
        "-signer", catfile($smdir, "smrsa2.pem"),
        "-signer", catfile($smdir, "smdsa1.pem"),
        "-signer", catfile($smdir, "smdsa2.pem"),
        "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms", "-inform", "DER",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "signed content test streaming BER format, 2 DSA and 2 RSA keys, no attributes",
      [ "{cmd1}", "-sign", "-in", $smcont, "-outform", "DER",
        "-noattr", "-nodetach", "-stream",
        "-signer", catfile($smdir, "smrsa1.pem"),
        "-signer", catfile($smdir, "smrsa2.pem"),
        "-signer", catfile($smdir, "smdsa1.pem"),
        "-signer", catfile($smdir, "smdsa2.pem"),
        "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms", "-inform", "DER",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "signed content S/MIME format, RSA key SHA1",
      [ "{cmd1}", "-sign", "-in", $smcont, "-md", "sha1",
        "-certfile", catfile($smdir, "smroot.pem"),
        "-signer", catfile($smdir, "smrsa1.pem"), "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "signed content test streaming S/MIME format, 2 DSA and 2 RSA keys",
      [ "{cmd1}", "-sign", "-in", $smcont, "-nodetach",
        "-signer", catfile($smdir, "smrsa1.pem"),
        "-signer", catfile($smdir, "smrsa2.pem"),
        "-signer", catfile($smdir, "smdsa1.pem"),
        "-signer", catfile($smdir, "smdsa2.pem"),
        "-stream", "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "signed content test streaming multipart S/MIME format, 2 DSA and 2 RSA keys",
      [ "{cmd1}", "-sign", "-in", $smcont,
        "-signer", catfile($smdir, "smrsa1.pem"),
        "-signer", catfile($smdir, "smrsa2.pem"),
        "-signer", catfile($smdir, "smdsa1.pem"),
        "-signer", catfile($smdir, "smdsa2.pem"),
        "-stream", "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "enveloped content test streaming S/MIME format, DES, 3 recipients",
      [ "{cmd1}", "-encrypt", "-in", $smcont,
        "-stream", "-out", "{output}.cms",
        catfile($smdir, "smrsa1.pem"),
        catfile($smdir, "smrsa2.pem"),
        catfile($smdir, "smrsa3.pem") ],
      [ "{cmd2}", "-decrypt", "-recip", catfile($smdir, "smrsa1.pem"),
        "-in", "{output}.cms", "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "enveloped content test streaming S/MIME format, DES, 3 recipients, 3rd used",
      [ "{cmd1}", "-encrypt", "-in", $smcont,
        "-stream", "-out", "{output}.cms",
        catfile($smdir, "smrsa1.pem"),
        catfile($smdir, "smrsa2.pem"),
        catfile($smdir, "smrsa3.pem") ],
      [ "{cmd2}", "-decrypt", "-recip", catfile($smdir, "smrsa3.pem"),
        "-in", "{output}.cms", "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "enveloped content test streaming S/MIME format, DES, 3 recipients, key only used",
      [ "{cmd1}", "-encrypt", "-in", $smcont,
        "-stream", "-out", "{output}.cms",
        catfile($smdir, "smrsa1.pem"),
        catfile($smdir, "smrsa2.pem"),
        catfile($smdir, "smrsa3.pem") ],
      [ "{cmd2}", "-decrypt", "-inkey", catfile($smdir, "smrsa3.pem"),
        "-in", "{output}.cms", "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "enveloped content test streaming S/MIME format, AES-256 cipher, 3 recipients",
      [ "{cmd1}", "-encrypt", "-in", $smcont,
        "-aes256", "-stream", "-out", "{output}.cms",
        catfile($smdir, "smrsa1.pem"),
        catfile($smdir, "smrsa2.pem"),
        catfile($smdir, "smrsa3.pem") ],
      [ "{cmd2}", "-decrypt", "-recip", catfile($smdir, "smrsa1.pem"),
        "-in", "{output}.cms", "-out", "{output}.txt" ],
      \&final_compare
    ],

);

my @smime_cms_tests = (

    [ "signed content test streaming BER format, 2 DSA and 2 RSA keys, keyid",
      [ "{cmd1}", "-sign", "-in", $smcont, "-outform", "DER",
        "-nodetach", "-keyid",
        "-signer", catfile($smdir, "smrsa1.pem"),
        "-signer", catfile($smdir, "smrsa2.pem"),
        "-signer", catfile($smdir, "smdsa1.pem"),
        "-signer", catfile($smdir, "smdsa2.pem"),
        "-stream", "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms", "-inform", "DER",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "signed content test streaming PEM format, 2 DSA and 2 RSA keys",
      [ "{cmd1}", "-sign", "-in", $smcont, "-outform", "PEM", "-nodetach",
        "-signer", catfile($smdir, "smrsa1.pem"),
        "-signer", catfile($smdir, "smrsa2.pem"),
        "-signer", catfile($smdir, "smdsa1.pem"),
        "-signer", catfile($smdir, "smdsa2.pem"),
        "-stream", "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms", "-inform", "PEM",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "signed content MIME format, RSA key, signed receipt request",
      [ "{cmd1}", "-sign", "-in", $smcont, "-nodetach",
        "-signer", catfile($smdir, "smrsa1.pem"),
        "-receipt_request_to", "test\@openssl.org", "-receipt_request_all",
        "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "signed receipt MIME format, RSA key",
      [ "{cmd1}", "-sign", "-in", $smcont, "-nodetach",
        "-signer", catfile($smdir, "smrsa1.pem"),
        "-receipt_request_to", "test\@openssl.org", "-receipt_request_all",
        "-out", "{output}.cms" ],
      [ "{cmd1}", "-sign_receipt", "-in", "{output}.cms",
        "-signer", catfile($smdir, "smrsa2.pem"), "-out", "{output}2.cms" ],
      [ "{cmd2}", "-verify_receipt", "{output}2.cms", "-in", "{output}.cms",
        "-CAfile", catfile($smdir, "smroot.pem") ]
    ],

    [ "signed content DER format, RSA key, CAdES-BES compatible",
      [ "{cmd1}", "-sign", "-cades", "-in", $smcont, "-outform", "DER",
        "-nodetach",
        "-certfile", catfile($smdir, "smroot.pem"),
        "-signer", catfile($smdir, "smrsa1.pem"), "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms", "-inform", "DER",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "signed content DER format, RSA key, SHA256 md, CAdES-BES compatible",
      [ "{cmd1}", "-sign", "-cades", "-md", "sha256", "-in", $smcont,
        "-outform", "DER", "-nodetach",
        "-certfile", catfile($smdir, "smroot.pem"),
        "-signer", catfile($smdir, "smrsa1.pem"), "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms", "-inform", "DER",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "enveloped content test streaming S/MIME format, DES, 3 recipients, keyid",
      [ "{cmd1}", "-encrypt", "-in", $smcont,
        "-stream", "-out", "{output}.cms", "-keyid",
        catfile($smdir, "smrsa1.pem"),
        catfile($smdir, "smrsa2.pem"),
        catfile($smdir, "smrsa3.pem") ],
      [ "{cmd2}", "-decrypt", "-recip", catfile($smdir, "smrsa1.pem"),
        "-in", "{output}.cms", "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "enveloped content test streaming PEM format, KEK",
      [ "{cmd1}", "-encrypt", "-in", $smcont, "-outform", "PEM", "-aes128",
        "-stream", "-out", "{output}.cms",
        "-secretkey", "000102030405060708090A0B0C0D0E0F",
        "-secretkeyid", "C0FEE0" ],
      [ "{cmd2}", "-decrypt", "-in", "{output}.cms", "-out", "{output}.txt",
        "-inform", "PEM",
        "-secretkey", "000102030405060708090A0B0C0D0E0F",
        "-secretkeyid", "C0FEE0" ],
      \&final_compare
    ],

    [ "enveloped content test streaming PEM format, KEK, key only",
      [ "{cmd1}", "-encrypt", "-in", $smcont, "-outform", "PEM", "-aes128",
        "-stream", "-out", "{output}.cms",
        "-secretkey", "000102030405060708090A0B0C0D0E0F",
        "-secretkeyid", "C0FEE0" ],
      [ "{cmd2}", "-decrypt", "-in", "{output}.cms", "-out", "{output}.txt",
        "-inform", "PEM",
        "-secretkey", "000102030405060708090A0B0C0D0E0F" ],
      \&final_compare
    ],

    [ "data content test streaming PEM format",
      [ "{cmd1}", "-data_create", "-in", $smcont, "-outform", "PEM",
        "-nodetach", "-stream", "-out", "{output}.cms" ],
      [ "{cmd2}", "-data_out", "-in", "{output}.cms", "-inform", "PEM",
        "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "encrypted content test streaming PEM format, 128 bit RC2 key",
      [ "{cmd1}", "-EncryptedData_encrypt", "-in", $smcont, "-outform", "PEM",
        "-rc2", "-secretkey", "000102030405060708090A0B0C0D0E0F",
        "-stream", "-out", "{output}.cms" ],
      [ "{cmd2}", "-EncryptedData_decrypt", "-in", "{output}.cms",
        "-inform", "PEM",
        "-secretkey", "000102030405060708090A0B0C0D0E0F",
        "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "encrypted content test streaming PEM format, 40 bit RC2 key",
      [ "{cmd1}", "-EncryptedData_encrypt", "-in", $smcont, "-outform", "PEM",
        "-rc2", "-secretkey", "0001020304",
        "-stream", "-out", "{output}.cms" ],
      [ "{cmd2}", "-EncryptedData_decrypt", "-in", "{output}.cms",
        "-inform", "PEM",
        "-secretkey", "0001020304", "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "encrypted content test streaming PEM format, triple DES key",
      [ "{cmd1}", "-EncryptedData_encrypt", "-in", $smcont, "-outform", "PEM",
        "-des3", "-secretkey", "000102030405060708090A0B0C0D0E0F1011121314151617",
        "-stream", "-out", "{output}.cms" ],
      [ "{cmd2}", "-EncryptedData_decrypt", "-in", "{output}.cms",
        "-inform", "PEM",
        "-secretkey", "000102030405060708090A0B0C0D0E0F1011121314151617",
        "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "encrypted content test streaming PEM format, 128 bit AES key",
      [ "{cmd1}", "-EncryptedData_encrypt", "-in", $smcont, "-outform", "PEM",
        "-aes128", "-secretkey", "000102030405060708090A0B0C0D0E0F",
        "-stream", "-out", "{output}.cms" ],
      [ "{cmd2}", "-EncryptedData_decrypt", "-in", "{output}.cms",
        "-inform", "PEM",
        "-secretkey", "000102030405060708090A0B0C0D0E0F",
        "-out", "{output}.txt" ],
      \&final_compare
    ],

);

my @smime_cms_comp_tests = (

    [ "compressed content test streaming PEM format",
      [ "{cmd1}", "-compress", "-in", $smcont, "-outform", "PEM", "-nodetach",
        "-stream", "-out", "{output}.cms" ],
      [ "{cmd2}", "-uncompress", "-in", "{output}.cms", "-inform", "PEM",
        "-out", "{output}.txt" ],
      \&final_compare
    ]

);

my @smime_cms_param_tests = (
    [ "signed content test streaming PEM format, RSA keys, PSS signature",
      [ "{cmd1}", "-sign", "-in", $smcont, "-outform", "PEM", "-nodetach",
        "-signer", catfile($smdir, "smrsa1.pem"),
        "-keyopt", "rsa_padding_mode:pss",
        "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms", "-inform", "PEM",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "signed content test streaming PEM format, RSA keys, PSS signature, saltlen=max",
      [ "{cmd1}", "-sign", "-in", $smcont, "-outform", "PEM", "-nodetach",
        "-signer", catfile($smdir, "smrsa1.pem"),
        "-keyopt", "rsa_padding_mode:pss", "-keyopt", "rsa_pss_saltlen:max",
        "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms", "-inform", "PEM",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "signed content test streaming PEM format, RSA keys, PSS signature, no attributes",
      [ "{cmd1}", "-sign", "-in", $smcont, "-outform", "PEM", "-nodetach",
        "-noattr",
        "-signer", catfile($smdir, "smrsa1.pem"),
        "-keyopt", "rsa_padding_mode:pss",
        "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms", "-inform", "PEM",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "signed content test streaming PEM format, RSA keys, PSS signature, SHA384 MGF1",
      [ "{cmd1}", "-sign", "-in", $smcont, "-outform", "PEM", "-nodetach",
        "-signer", catfile($smdir, "smrsa1.pem"),
        "-keyopt", "rsa_padding_mode:pss", "-keyopt", "rsa_mgf1_md:sha384",
        "-out", "{output}.cms" ],
      [ "{cmd2}", "-verify", "-in", "{output}.cms", "-inform", "PEM",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "enveloped content test streaming S/MIME format, DES, OAEP default parameters",
      [ "{cmd1}", "-encrypt", "-in", $smcont,
        "-stream", "-out", "{output}.cms",
        "-recip", catfile($smdir, "smrsa1.pem"),
        "-keyopt", "rsa_padding_mode:oaep" ],
      [ "{cmd2}", "-decrypt", "-recip", catfile($smdir, "smrsa1.pem"),
        "-in", "{output}.cms", "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "enveloped content test streaming S/MIME format, DES, OAEP SHA256",
      [ "{cmd1}", "-encrypt", "-in", $smcont,
        "-stream", "-out", "{output}.cms",
        "-recip", catfile($smdir, "smrsa1.pem"),
        "-keyopt", "rsa_padding_mode:oaep",
        "-keyopt", "rsa_oaep_md:sha256" ],
      [ "{cmd2}", "-decrypt", "-recip", catfile($smdir, "smrsa1.pem"),
        "-in", "{output}.cms", "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "enveloped content test streaming S/MIME format, DES, ECDH",
      [ "{cmd1}", "-encrypt", "-in", $smcont,
        "-stream", "-out", "{output}.cms",
        "-recip", catfile($smdir, "smec1.pem") ],
      [ "{cmd2}", "-decrypt", "-recip", catfile($smdir, "smec1.pem"),
        "-in", "{output}.cms", "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "enveloped content test streaming S/MIME format, DES, ECDH, 2 recipients, key only used",
      [ "{cmd1}", "-encrypt", "-in", $smcont,
        "-stream", "-out", "{output}.cms",
        catfile($smdir, "smec1.pem"),
        catfile($smdir, "smec3.pem") ],
      [ "{cmd2}", "-decrypt", "-inkey", catfile($smdir, "smec3.pem"),
        "-in", "{output}.cms", "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "enveloped content test streaming S/MIME format, ECDH, DES, key identifier",
      [ "{cmd1}", "-encrypt", "-keyid", "-in", $smcont,
        "-stream", "-out", "{output}.cms",
        "-recip", catfile($smdir, "smec1.pem") ],
      [ "{cmd2}", "-decrypt", "-recip", catfile($smdir, "smec1.pem"),
        "-in", "{output}.cms", "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "enveloped content test streaming S/MIME format, ECDH, AES128, SHA256 KDF",
      [ "{cmd1}", "-encrypt", "-in", $smcont,
        "-stream", "-out", "{output}.cms",
        "-recip", catfile($smdir, "smec1.pem"), "-aes128",
        "-keyopt", "ecdh_kdf_md:sha256" ],
      [ "{cmd2}", "-decrypt", "-recip", catfile($smdir, "smec1.pem"),
        "-in", "{output}.cms", "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "enveloped content test streaming S/MIME format, ECDH, K-283, cofactor DH",
      [ "{cmd1}", "-encrypt", "-in", $smcont,
        "-stream", "-out", "{output}.cms",
        "-recip", catfile($smdir, "smec2.pem"), "-aes128",
        "-keyopt", "ecdh_kdf_md:sha256", "-keyopt", "ecdh_cofactor_mode:1" ],
      [ "{cmd2}", "-decrypt", "-recip", catfile($smdir, "smec2.pem"),
        "-in", "{output}.cms", "-out", "{output}.txt" ],
      \&final_compare
    ],

    [ "enveloped content test streaming S/MIME format, X9.42 DH",
      [ "{cmd1}", "-encrypt", "-in", $smcont,
        "-stream", "-out", "{output}.cms",
        "-recip", catfile($smdir, "smdh.pem"), "-aes128" ],
      [ "{cmd2}", "-decrypt", "-recip", catfile($smdir, "smdh.pem"),
        "-in", "{output}.cms", "-out", "{output}.txt" ],
      \&final_compare
    ]
    );

my @contenttype_cms_test = (
    [ "signed content test - check that content type is added to additional signerinfo, RSA keys",
      [ "{cmd1}", "-sign", "-binary", "-nodetach", "-stream", "-in", $smcont,
        "-outform", "DER",
        "-signer", catfile($smdir, "smrsa1.pem"), "-md", "SHA256",
        "-out", "{output}.cms" ],
      [ "{cmd1}", "-resign", "-binary", "-nodetach", "-in", "{output}.cms",
        "-inform", "DER", "-outform", "DER",
        "-signer", catfile($smdir, "smrsa2.pem"), "-md", "SHA256",
        "-out", "{output}2.cms" ],
      sub { my %opts = @_; contentType_matches("$opts{output}2.cms") == 2; },
      [ "{cmd2}", "-verify", "-in", "{output}2.cms", "-inform", "DER",
        "-CAfile", catfile($smdir, "smroot.pem"), "-out", "{output}.txt" ]
    ],
);

my @incorrect_attribute_cms_test = (
    "bad_signtime_attr.cms",
    "no_ct_attr.cms",
    "no_md_attr.cms",
    "ct_multiple_attr.cms"
);

# Runs a standard loop on the input array
sub runner_loop {
    my %opts = ( @_ );
    my $cnt1 = 0;

    foreach (@{$opts{tests}}) {
        $cnt1++;
        $opts{output} = "$opts{prefix}-$cnt1";
      SKIP: {
          my $skip_reason = check_availability($$_[0]);
          skip $skip_reason, 1 if $skip_reason;
          my $ok = 1;
          1 while unlink "$opts{output}.txt";

          foreach (@$_[1..$#$_]) {
              if (ref $_ eq 'CODE') {
                  $ok &&= $_->(%opts);
              } else {
                  my @cmd = map {
                      my $x = $_;
                      while ($x =~ /\{([^\}]+)\}/) {
                          $x = $`.$opts{$1}.$' if exists $opts{$1};
                      }
                      $x;
                  } @$_;

                  diag "CMD: openssl", join(" ", @cmd);
                  $ok &&= run(app(["openssl", @cmd]));
                  $opts{input} = $opts{output};
              }
          }

          ok($ok, $$_[0]);
        }
    }
}

sub final_compare {
    my %opts = @_;

    diag "Comparing $smcont with $opts{output}.txt";
    return compare_text($smcont, "$opts{output}.txt") == 0;
}

subtest "CMS => PKCS#7 compatibility tests\n" => sub {
    plan tests => scalar @smime_pkcs7_tests;

    runner_loop(prefix => 'cms2pkcs7', cmd1 => 'cms', cmd2 => 'smime',
                tests => [ @smime_pkcs7_tests ]);
};
subtest "CMS <= PKCS#7 compatibility tests\n" => sub {
    plan tests => scalar @smime_pkcs7_tests;

    runner_loop(prefix => 'pkcs72cms', cmd1 => 'smime', cmd2 => 'cms',
                tests => [ @smime_pkcs7_tests ]);
};

subtest "CMS <=> CMS consistency tests\n" => sub {
    plan tests => (scalar @smime_pkcs7_tests) + (scalar @smime_cms_tests);

    runner_loop(prefix => 'cms2cms-1', cmd1 => 'cms', cmd2 => 'cms',
                tests => [ @smime_pkcs7_tests ]);
    runner_loop(prefix => 'cms2cms-2', cmd1 => 'cms', cmd2 => 'cms',
                tests => [ @smime_cms_tests ]);
};

subtest "CMS <=> CMS consistency tests, modified key parameters\n" => sub {
    plan tests =>
        (scalar @smime_cms_param_tests) + (scalar @smime_cms_comp_tests);

    runner_loop(prefix => 'cms2cms-mod', cmd1 => 'cms', cmd2 => 'cms',
                tests => [ @smime_cms_param_tests ]);
  SKIP: {
      skip("Zlib not supported: compression tests skipped",
           scalar @smime_cms_comp_tests)
          if $no_zlib;

      runner_loop(prefix => 'cms2cms-comp', cmd1 => 'cms', cmd2 => 'cms',
                  tests => [ @smime_cms_comp_tests ]);
    }
};

# Returns the number of matches of a Content Type Attribute in a binary file.
sub contentType_matches {
  # Read in a binary file
  my ($in) = @_;
  open (HEX_IN, "$in") or die("open failed for $in : $!");
  binmode(HEX_IN);
  local $/;
  my $str = <HEX_IN>;

  # Find ASN1 data for a Content Type Attribute (with a OID of PKCS7 data)
  my @c = $str =~ /\x30\x18\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x03\x31\x0B\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x01/gs;

  close(HEX_IN);
  return scalar(@c);
}

subtest "CMS Check the content type attribute is added for additional signers\n" => sub {
    plan tests => (scalar @contenttype_cms_test);

    runner_loop(prefix => 'cms2cms-added', cmd1 => 'cms', cmd2 => 'cms',
                tests => [ @contenttype_cms_test ]);
};

subtest "CMS Check that bad attributes fail when verifying signers\n" => sub {
    plan tests =>
        (scalar @incorrect_attribute_cms_test);

    my $cnt = 0;
    foreach my $name (@incorrect_attribute_cms_test) {
        my $out = "incorrect-$cnt.txt";

        ok(!run(app(["openssl", "cms", "-verify", "-in",
                     catfile($datadir, $name), "-inform", "DER", "-CAfile",
                     catfile($smdir, "smroot.pem"), "-out", $out ])),
            $name);
    }
};

subtest "CMS Decrypt message encrypted with OpenSSL 1.1.1\n" => sub {
    plan tests => 1;

    SKIP: {
        skip "EC isn't supported in this build", 1
            if disabled("ec");

        my $out = "smtst.txt";

        ok(run(app(["openssl", "cms", "-decrypt",
                    "-inkey", catfile($smdir, "smec3.pem"),
                    "-in", catfile($datadir, "ciphertext_from_1_1_1.cms"),
                    "-out", $out ]))
           && compare_text($smcont, $out) == 0,
           "Decrypt message from OpenSSL 1.1.1");
    }
};

sub check_availability {
    my $tnam = shift;

    return "$tnam: skipped, EC disabled\n"
        if ($no_ec && $tnam =~ /ECDH/);
    return "$tnam: skipped, ECDH disabled\n"
        if ($no_ec && $tnam =~ /ECDH/);
    return "$tnam: skipped, EC2M disabled\n"
        if ($no_ec2m && $tnam =~ /K-283/);
    return "$tnam: skipped, DH disabled\n"
        if ($no_dh && $tnam =~ /X9\.42/);
    return "$tnam: skipped, RC2 disabled\n"
        if ($no_rc2 && $tnam =~ /RC2/);
    return "$tnam: skipped, DES disabled\n"
        if ($no_des && $tnam =~ /DES/);
    return "$tnam: skipped, DSA disabled\n"
        if ($no_dsa && $tnam =~ / DSA/);

    return "";
}
