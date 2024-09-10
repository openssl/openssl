#! /usr/bin/env perl
# Copyright 2020-2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#

use strict;
use warnings;

use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file srctop_dir bldtop_dir bldtop_file with/;

setup("test_app_ech");

plan skip_all => "ECH tests not supported in this build"
    if disabled("ech") || disabled("tls1_3")
       || disabled("ec") || disabled("ecx");

plan tests => 13;

ok(run(app(["openssl", "ech", "-help"])),
   "Run openssl ech with help");
ok(run(app(["openssl", "ech",
                "-ech_version", "13",
                "-public_name", "example.com",
                "-out", "eg1.pem",
                "-verbose",
                "-text"])),
   "Generate an ECH key pair for example.com");
ok(run(app(["openssl", "ech",
                "-suite", "0x10,2,2",
                "-public_name", "example.com",
                "-out", "eg2.pem",
                "-text"])),
   "Generate an ECDSA ECH key pair for example.com");
ok(run(app(["openssl", "ech",
                "-max_name_len", "13",
                "-public_name", "example.com",
                "-out", "eg2.pem",
                "-text"])),
   "Generate an ECH key pair for example.com with max name len 13");
ok(run(app(["openssl", "ech",
                "-in", "eg1.pem",
                "-in", "eg2.pem",
                "-out", "eg3.pem",
                "-verbose"])),
   "Catenate the ECH for example.com twice");
ok(run(app(["openssl", "ech",
                "-in", "eg3.pem",
                "-select", "1",
                "-verbose",
                "-out", "eg4.pem"])),
   "Select one ECH Config");

with({ exit_checker => sub { return shift == 1; } },
    sub { 
		ok(run(app(["openssl", "ech" ])),
		   "Run openssl ech with no arg");
		ok(run(app(["openssl", "ech", "-nohelpatall"])),
		   "Run openssl ech with unknown arg");
		ok(run(app(["openssl", "ech", "nohelpatall"])),
		   "Run openssl ech with unknown non arg");
		ok(run(app(["openssl", "ech",
		                "-ech_version", "0xfe09",
		                "-public_name", "example.com",
		                "-out", "eg1.pem",
		                "-text"])),
		   "Fail to generate an ECH key pair for old draft version");
		ok(run(app(["openssl", "ech",
		                "-suite", "not,a,good,one",
		                "-public_name", "example.com",
		                "-out", "eg2.pem",
		                "-text"])),
		   "Fail to generate an ECH key pair with bad suite");
		ok(run(app(["openssl", "ech",
		                "-max_name_len", "1300",
		                "-public_name", "example.com",
		                "-text"])),
		   "(Fail to) Generate an ECH key pair for example.com with max name len 1300");
		ok(run(app(["openssl", "ech",
		                "-in", "eg1.pem",
		                "-in", "eg2.pem",
		                "-in", "eg3.pem",
		                "-in", "eg4.pem",
		                "-in", "eg1.pem",
		                "-in", "eg2.pem",
		                "-in", "eg3.pem",
		                "-in", "eg4.pem"])),
		   "Too many input files");
});
