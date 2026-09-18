#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Compare qw/compare_text/;
use OpenSSL::Test qw/:DEFAULT data_file/;
use OpenSSL::Test::Utils;

setup("test_mlx_codecs");

plan skip_all => "MLX KEMs aren't supported in this build"
    if disabled("ml-kem") || disabled("ecx");

plan tests => 13;

my $seed = "7f9c2ba4e88f827d616045507605853e"
    . "d73b8093f6efbc88eb1a6eacfa66ef26";
my $prvpem = "xwing-prv.pem";
my $prvtxt = "xwing-prv.txt";
my $pubpem = "xwing-pub.pem";
my $pubtxt = "xwing-pub.txt";
my $encpem = "xwing-prv-enc.pem";
my $decpem = "xwing-prv-dec.pem";
my $expecteddecpem = "xwing-prv-expected-dec.pem";
my $password = "pass:xwing-test-password";

ok(run(app(['openssl', 'genpkey', '-algorithm', 'X-Wing',
            '-pkeyopt', "hexseed:$seed", '-out', $prvpem])),
   "generate X-Wing private key");
ok(!compare_text(data_file("xwing-prv.pem"), $prvpem),
   "X-Wing private key PEM matches");
ok(run(app(['openssl', 'pkey', '-in', $prvpem, '-noout', '-text',
            '-out', $prvtxt])),
   "encode X-Wing private key as text");
ok(!compare_text(data_file("xwing-prv.txt"), $prvtxt),
   "X-Wing private key text matches");

ok(run(app(['openssl', 'pkey', '-in', $prvpem, '-pubout',
            '-out', $pubpem])),
   "encode X-Wing public key");
ok(!compare_text(data_file("xwing-pub.pem"), $pubpem),
   "X-Wing public key PEM matches");
ok(run(app(['openssl', 'pkey', '-pubin', '-in', $pubpem, '-noout',
            '-text', '-out', $pubtxt])),
   "encode X-Wing public key as text");
ok(!compare_text(data_file("xwing-pub.txt"), $pubtxt),
   "X-Wing public key text matches");

ok(run(app(['openssl', 'pkey', '-in', data_file("xwing-prv.pem"),
            '-aes256', '-passout', $password, '-out', $encpem])),
   "encrypt X-Wing private key");
ok(run(app(['openssl', 'pkey', '-in', $encpem, '-passin', $password,
            '-out', $decpem])),
   "decrypt X-Wing private key");
ok(!compare_text(data_file("xwing-prv.pem"), $decpem),
   "decrypted X-Wing private key PEM matches");

ok(run(app(['openssl', 'pkey',
            '-in', data_file("xwing-prv-enc.pem"),
            '-passin', $password, '-out', $expecteddecpem])),
   "decrypt expected encrypted X-Wing private key");
ok(!compare_text(data_file("xwing-prv.pem"), $expecteddecpem),
   "expected encrypted X-Wing private key decrypts correctly");
