#! /usr/bin/env perl
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use File::Copy;
use File::Spec::Functions qw/curdir/;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

$ENV{ASAN_OPTIONS} = "detect_leaks=1";

setup("test_load_cert_file");

plan tests => 1;

indir "certdir" => sub {
    my $chain = srctop_file("test", "certs", "leaf-chain.pem");
    my @hash = run(app(["openssl", "x509", "-in", $chain, "-subject_hash", "-noout"]),
                   capture => 1);
    chomp $hash[0];
    copy($chain, "$hash[0].0") or die "Cannot copy certificate chain: $!";
    open my $empty, ">", "$hash[0].1"
        or die "Cannot create empty certificate file: $!";
    close $empty or die "Cannot close empty certificate file: $!";

    ok(run(test(["x509_load_cert_file_test", $chain,
                 srctop_file("test", "certs", "cyrillic_crl.pem"), curdir()])));
}, create => 1, cleanup => 1;
