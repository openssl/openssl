#! /usr/bin/env perl
# Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
# Copyright 2017 BaishanCloud. All rights reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT data_file/;
use OpenSSL::Test::Utils;

setup("test_mp_rsa");

plan tests => 61;

ok(run(test(["rsa_mp_test"])), "running rsa multi prime test");

my $cleartext = data_file("plain_text");

my @test_param = (
    # 3 primes, 2048-bit
    {
        primes => '3',
        bits => '2048',
    },
    # 4 primes, 2048-bit
    {
        primes => '4',
        bits => '2048',
    },
    # 8 primes, 2048-bit
    {
        primes => '8',
        bits => '2048',
    },
    # 15 primes, 2048-bit
    {
        primes => '15',
        bits => '2048',
    },
    # 8 primes, 15360-bit (3 & 4 primes for 15360 bit is too long to gen a key)
    {
        primes => '8',
        bits => '15360',
    },
    # 15 primes, 15360-bit
    {
        primes => '15',
        bits => '15360',
    },
);

# genrsa
run_mp_tests(0);
# evp
run_mp_tests(1);

sub run_mp_tests {
    my $evp = shift;

    foreach my $param (@test_param) {
        my $primes = $param->{primes};
        my $bits = $param->{bits};
        my $name = ($evp ? "evp" : "") . "${bits}p${primes}";

        if ($evp) {
            ok(run(app([ 'openssl', 'genpkey', '-out', 'rsamptest.pem',
                         '-algorithm', 'RSA', '-pkeyopt', "rsa_keygen_primes:$primes",
                         '-pkeyopt', "rsa_keygen_bits:$bits"])), "genrsa $name");
        } else {
            ok(run(app([ 'openssl', 'genrsa', '-out', 'rsamptest.pem',
                         '-primes', $primes, $bits])), "genrsa $name");
        }

        ok(run(app([ 'openssl', 'rsa', '-check', '-in', 'rsamptest.pem',
                     '-noout'])), "rsa -check $name");
        if ($evp) {
            ok(run(app([ 'openssl', 'pkeyutl', '-inkey', 'rsamptest.pem',
                         '-encrypt', '-in', $cleartext,
                         '-out', 'rsamptest.enc' ])), "rsa $name encrypt");
            ok(run(app([ 'openssl', 'pkeyutl', '-inkey', 'rsamptest.pem',
                         '-decrypt', '-in', 'rsamptest.enc',
                         '-out', 'rsamptest.dec' ])), "rsa $name decrypt");
        } else {
            ok(run(app([ 'openssl', 'rsautl', '-inkey', 'rsamptest.pem',
                         '-encrypt', '-in', $cleartext,
                         '-out', 'rsamptest.enc' ])), "rsa $name encrypt");
            ok(run(app([ 'openssl', 'rsautl', '-inkey', 'rsamptest.pem',
                         '-decrypt', '-in', 'rsamptest.enc',
                         '-out', 'rsamptest.dec' ])), "rsa $name decrypt");
        }

        ok(check_msg(), "rsa $name check result");

        # clean up temp files
        unlink 'rsamptest.pem';
        unlink 'rsamptest.enc';
        unlink 'rsamptest.dec';
    }
}

sub check_msg {
    my $msg;
    my $dec;

    open(my $fh, "<", $cleartext) or return 0;
    binmode $fh;
    read($fh, $msg, 10240);
    close $fh;
    open($fh, "<", "rsamptest.dec") or return 0;
    binmode $fh;
    read($fh, $dec, 10240);
    close $fh;

    if ($msg ne $dec) {
        print STDERR "cleartext and decrypted are not the same";
        return 0;
    }
    return 1;
}
