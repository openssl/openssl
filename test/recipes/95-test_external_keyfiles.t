#! /usr/bin/env perl
# Copyright 2015-2021 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use File::Copy;
use OpenSSL::Test;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT data_file bldtop_dir bldtop_file srctop_dir srctop_file cmdstr/;

setup("test_external_keyfiles");

plan skip_all => "No external tests in this configuration"
    if disabled("external-tests");

my @p12_files = glob(srctop_file("keyfile-corpus", "*.p12"));

# Skip malformed files
@p12_files = grep(!/malformed/, @p12_files);

# Skip files with separate cipher/mac passwords
@p12_files = grep(!/pass-cipher/, @p12_files);

# Skip files with an empty password - pkcs12 app cannot handle this
@p12_files = grep(!/pass\(empty/, @p12_files);

@p12_files = grep(!/MD2/, @p12_files) if disabled("md2");

plan tests => scalar(@p12_files) * 2;

my $fnum = 1;

foreach my $p12 ( @p12_files ) {

    my $passfile = srctop_file("keyfile-corpus", "password-ascii.txt");
    my $provider_path = bldtop_dir("providers");

    # Some files specify a different password
    $passfile = srctop_file("keyfile-corpus", "password-unicode.txt") if $p12 =~ /pass\(unicode/;
    $passfile = srctop_file("keyfile-corpus", "password-empty.txt") if $p12 =~ /pass\(empty/;

    ok(copy($p12, "kf-$fnum.p12"));

    ok(run(app(["openssl", "pkcs12",
                 "-noout",
                 #"-info",
                 "-in", "kf-$fnum.p12",
                 "-provider-path=$provider_path",
                 "-provider", "legacy",
                 "-provider", "default",
                 #"-nokeys",  NOTE: pkcs12 app does not allow key password as an argument, yet.
                 "-password", "file:$passfile"])),
       "running openssl pkcs12 with file kf-$fnum.p12 ($p12)");

    $fnum = $fnum + 1;
}


