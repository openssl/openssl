#! /usr/bin/env perl
# Copyright 2015-2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use POSIX;
use File::Spec::Functions qw/catfile/;
use File::Compare qw/compare_text compare/;
use OpenSSL::Test qw/:DEFAULT srctop_dir srctop_file bldtop_dir bldtop_file with data_file/;

use OpenSSL::Test::Utils;

BEGIN {
    setup("test_cms_cades_t");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

plan skip_all => "CMS is not supported by this OpenSSL build"
    if disabled("cms");

my $datadir = srctop_dir("test", "recipes", "80-test_cms_cades_t_data");
my $smdir    = srctop_dir("test", "smime-certs");
my $smcont   = srctop_file("test", "smcont.txt");
my $catsacnf = srctop_file("test", "catsa.cnf");
my $smcont_zero = srctop_file("test", "smcont_zero.txt");
my ($no_des, $no_dh, $no_dsa, $no_ec, $no_ec2m, $no_rc2, $no_zlib)
    = disabled qw/des dh dsa ec ec2m rc2 zlib/;

plan tests => 1;

my $smrsa1024 = catfile($smdir, "smrsa1024.pem");
my $smrsa1 = catfile($smdir, "smrsa1.pem");
my $smroot = catfile($smdir, "smroot.pem");

subtest "CMS code signing with CAdES Baseline-T test" => sub {
    plan tests => 12;
    my $tmp_sig_file = "tmp_signature.p7s";
    my $dgst_sig_file = "signature.bin";
    my $sig_file = "signature.p7s";
    my $req_file = "request.tsq";
    my $resp_file = "response.tsr";
    my $expired_sig_file = catfile($datadir, "expired_signature_cades_t.cms");

    ok(run(app(["openssl", "cms", "-sign", "-cades", "-in", $smcont,
                   "-certfile", catfile($smdir, "smroot.pem"),
                   "-signer", catfile($smdir, "csrsa1.pem"),
                   "-out", $tmp_sig_file,
                   "-outform", "DER",
                   "-signature", $dgst_sig_file])),
        "accept perform CMS signature with code signing certificate and export internal signature digest");

    ok(run(app(["openssl", "ts", "-query", "-config", $catsacnf,
                   "-data", $dgst_sig_file,
                   "-cert", "-sha256", "-no_nonce",
                   "-out", $req_file])),
        "accept create timestamp request for signature digest");

    ok(run(app(["openssl", "ts", "-reply", "-config", $catsacnf,
                   "-queryfile", $req_file,
                   "-chain", catfile($smdir, "smroot.pem"), # overrides "cert" in config file
                   "-signer", catfile($smdir, "tsrsa1.pem"),
                   "-inkey", catfile($smdir, "tsrsa1.pem"),
                   "-out", $resp_file])),
        "accept create timestamp response for signature digest");

    # ts -reply does not fail hard but encodes error messages into the
    # response. Therefore the reply has to be tested explicitly.
    ok(run(app(["openssl", "ts", "-verify", "-config", $catsacnf,
                   "-data", $dgst_sig_file,
                   "-CAfile", catfile($smdir, "smroot.pem"),
                   "-in", $resp_file])),
        "accept verify timestamp response for signature digest");

    ok(run(app(["openssl", "cms", "-cades",
                   "-extend_signature_tst", $resp_file,
                   "-in", $tmp_sig_file, "-inform", "DER",
                   "-out", $sig_file, "-outform", "DER"])),
        "accept extend CMS signature with timestamp to reach CAdES Baseline-T");

    ok(run(app(["openssl", "cms", "-verify", "-cades", "-binary",
                    "-in", $sig_file, "-inform", "DER",
                    "-CAfile", catfile($smdir, "smroot.pem"),
                    "-purpose", "codesign",
                    "-content", $smcont])),
       "accept verify CMS signature with code signing certificate for purpose code signing in CAdES Baseline-T");

    # now repeat the same operation(s) but with openssl ts -reply providing
    # a timestamp token instead of a timestamp response

    ok(run(app(["openssl", "ts", "-reply", "-config", $catsacnf,
                   "-queryfile", $req_file,
                   "-chain", catfile($smdir, "smroot.pem"), # overrides "cert" in config file
                   "-signer", catfile($smdir, "tsrsa1.pem"),
                   "-inkey", catfile($smdir, "tsrsa1.pem"),
                   "-out", $resp_file, "-token_out"])),
        "accept create timestamp response for signature digest");

    # ts -reply does not fail hard but encodes error messages into the
    # response. Therefore the reply has to be tested explicitly.
    ok(run(app(["openssl", "ts", "-verify", "-config", $catsacnf,
                   "-data", $dgst_sig_file,
                   "-CAfile", catfile($smdir, "smroot.pem"),
                   "-in", $resp_file, "-token_in"])),
        "accept verify timestamp response for signature digest");

    ok(run(app(["openssl", "cms", "-cades",
                   "-extend_signature_tst", $resp_file, "-token_in",
                   "-in", $tmp_sig_file, "-inform", "DER",
                   "-out", $sig_file, "-outform", "DER"])),
        "accept extend CMS signature with timestamp to reach CAdES Baseline-T");

    ok(run(app(["openssl", "cms", "-verify", "-cades", "-binary",
                    "-in", $sig_file, "-inform", "DER",
                    "-CAfile", catfile($smdir, "smroot.pem"),
                    "-purpose", "codesign",
                    "-content", $smcont])),
       "accept verify CMS signature with code signing certificate for purpose code signing in CAdES Baseline-T");

    # test signature with an already expired certificate but with CAdES B-T
    # Shall fail without -cades but succeed with -cades
    ok(!run(app(["openssl", "cms", "-verify", "-binary",
                    "-in", $expired_sig_file, "-inform", "DER",
                    "-CAfile", catfile($smdir, "smroot.pem"),
                    "-purpose", "codesign",
                    "-content", $smcont])),
       "fail verify CMS signature with expired code signing certificate");

    ok(run(app(["openssl", "cms", "-verify", "-cades", "-binary",
                    "-in", $expired_sig_file, "-inform", "DER",
                    "-CAfile", catfile($smdir, "smroot.pem"),
                    "-purpose", "codesign",
                    "-content", $smcont])),
       "accept verify CMS signature with expired code signing certificate for purpose code signing in CAdES Baseline-T");
};

