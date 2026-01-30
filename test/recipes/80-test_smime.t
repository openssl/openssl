#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Spec::Functions qw/catfile/;
use File::Compare qw/compare_text/;
use OpenSSL::Test qw/:DEFAULT srctop_dir srctop_file bldtop_dir with/;
use OpenSSL::Test::Utils;

setup("test_smime");

plan skip_all => "smime is not supported by this OpenSSL build"
    if disabled("des");

my $smdir = srctop_dir("test", "smime-certs");
my $smcont = srctop_file("test", "smcont.txt");
my $smrsa1 = catfile($smdir, "smrsa1.pem");

my $provpath = bldtop_dir("providers");
my @defaultprov = ("-provider-path", $provpath, "-provider", "default");

plan tests => 2;

# Test smime encryption with default cipher (AES-256-CBC)
ok(run(app(["openssl", "smime", @defaultprov,
            "-encrypt", "-in", $smcont,
            "-out", "smime_enc_default.txt",
            $smrsa1])),
   "smime encrypt with default cipher");

# Test smime decryption
ok(run(app(["openssl", "smime", @defaultprov,
            "-decrypt", "-in", "smime_enc_default.txt",
            "-recip", $smrsa1,
            "-out", "smime_dec_default.txt"])) &&
   compare_text($smcont, "smime_dec_default.txt") == 0,
   "smime decrypt and verify content");
