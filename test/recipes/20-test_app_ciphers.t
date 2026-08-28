#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT with/;
use OpenSSL::Test::Utils;

setup("test_app_ciphers");

plan skip_all => "The ciphers app is not available in a no-sock build"
    if disabled("sock");
plan skip_all => "No TLS protocols are supported by this OpenSSL build"
    if alldisabled(available_protocols("tls"));

plan tests => 7;

my $base_status;
my @base = run(app(["openssl", "ciphers"]),
               capture => 1, statusvar => \$base_status);
my @names = map { s|\R||; split(/:/, $_) } @base;

subtest "ciphers lists cipher names in non-verbose mode" => sub {
    plan tests => 5;

    ok($base_status, "ciphers with no options runs successfully");
    is(scalar @base, 1, "the whole list is printed on a single line");
    ok(@names > 0, "the list is not empty");
    is(join(" ", grep { !/^[A-Za-z0-9_-]+$/ } @names), "",
       "the list holds colon-separated cipher names");
    with({ exit_checker => sub { return shift == 1; } },
        sub {
            ok(run(app(["openssl", "ciphers", "NOSUCHCIPHER"])),
               "an unknown cipher string is rejected");
        });
};

# Each verbose line is a SSL_CIPHER_description() of one listed cipher.
my $desc = qr/\S+\s+Kx=\S+\s+Au=\S+\s+Enc=\S+\s+Mac=\S+/;

subtest "ciphers -v describes each cipher" => sub {
    plan tests => 3;

    my $status;
    my @out = run(app(["openssl", "ciphers", "-v"]),
                  capture => 1, statusvar => \$status);
    chomp @out;
    ok($status, "ciphers -v runs successfully");
    is(scalar @out, scalar @names, "one description line per cipher");
    my @got = map { /^(\S+)\s+$desc$/ ? $1 : "BAD LINE: $_" } @out;
    is(join(":", @got), join(":", @names),
       "each line holds a full description of the listed cipher");
};

subtest "ciphers -V prefixes descriptions with cipher codes" => sub {
    plan tests => 3;

    my $status;
    my @out = run(app(["openssl", "ciphers", "-V"]),
                  capture => 1, statusvar => \$status);
    chomp @out;
    ok($status, "ciphers -V runs successfully");
    is(scalar @out, scalar @names, "one description line per cipher");
    my $code = qr/(?:0x[0-9A-F]{2},){1,3}0x[0-9A-F]{2}/;
    my @got = map { /^\s*$code - (\S+)\s+$desc$/ ? $1 : "BAD LINE: $_" } @out;
    is(join(":", @got), join(":", @names),
       "each line holds the cipher code and a full description");
};

subtest "ciphers -stdname prefixes descriptions with standard names" => sub {
    plan tests => 4;

    my $status;
    my @out = run(app(["openssl", "ciphers", "-stdname"]),
                  capture => 1, statusvar => \$status);
    chomp @out;
    ok($status, "ciphers -stdname runs successfully");
    is(scalar @out, scalar @names, "one description line per cipher");
    my @got = map { /^\S+\s+- (\S+)\s+$desc$/ ? $1 : "BAD LINE: $_" } @out;
    is(join(":", @got), join(":", @names),
       "each line holds the standard name and a full description");
    my @badstd = grep { !/^(?:TLS_\S+|UNKNOWN)\s/ } @out;
    is(join("\n", @badstd), "", "standard names are TLS_* or UNKNOWN");
};

subtest "ciphers -V -stdname combines codes and standard names" => sub {
    plan tests => 3;

    my $status;
    my @out = run(app(["openssl", "ciphers", "-V", "-stdname"]),
                  capture => 1, statusvar => \$status);
    chomp @out;
    ok($status, "ciphers -V -stdname runs successfully");
    my $code = qr/(?:0x[0-9A-F]{2},){1,3}0x[0-9A-F]{2}/;
    my @got = map { /^\s*$code - \S+\s+- (\S+)\s+$desc$/ ? $1 : "BAD LINE: $_" }
        @out;
    is(join(":", @got), join(":", @names),
       "each line holds the code, the standard name and a description");

    SKIP: {
        my @all = run(app(["openssl", "ciphers", "ALL"]), capture => 1);
        skip "AES128-SHA is not available", 1
            unless grep { /(?:^|:)AES128-SHA(?::|$)/ } map { s|\R||r } @all;

        # The TLSv1.3 ciphersuites are always prepended to the list.
        my @line = grep { / - AES128-SHA\s/ }
            run(app(["openssl", "ciphers", "-stdname", "AES128-SHA"]),
                capture => 1, statusvar => \$status);
        ok($status && @line == 1
           && $line[0] =~ /^TLS_RSA_WITH_AES_128_CBC_SHA\s+- AES128-SHA\s/,
           "AES128-SHA maps to the TLS_RSA_WITH_AES_128_CBC_SHA standard name");
    }
};

subtest "ciphers -psk includes PSK ciphers among the supported ones" => sub {
    plan skip_all => "PSK is not supported by this OpenSSL build"
        if disabled("psk");
    plan skip_all => "TLSv1.2 is not supported by this OpenSSL build"
        if disabled("tls1_2");

    plan tests => 3;

    my $status;
    my @psk = grep { /PSK/ }
        map { s|\R||; split(/:/, $_) }
        run(app(["openssl", "ciphers", "-s", "-psk", "PSK"]),
            capture => 1, statusvar => \$status);
    ok($status, "ciphers -s -psk runs successfully");
    ok(@psk > 0, "PSK ciphers are supported with -psk");

    @psk = grep { /PSK/ }
        map { s|\R||; split(/:/, $_) }
        run(app(["openssl", "ciphers", "-s", "PSK"]),
            capture => 1, statusvar => \$status);
    ok($status && @psk == 0, "PSK ciphers are not supported without -psk");
};

subtest "ciphers -ciphersuites configures the TLSv1.3 ciphersuites" => sub {
    plan skip_all => "TLSv1.3 is not supported by this OpenSSL build"
        if disabled("tls1_3");

    plan tests => 3;

    my $status;
    my @suites = grep { /^TLS_/ }
        map { s|\R||; split(/:/, $_) }
        run(app(["openssl", "ciphers", "-ciphersuites",
                 "TLS_AES_128_GCM_SHA256"]),
            capture => 1, statusvar => \$status);
    ok($status, "ciphers -ciphersuites runs successfully");
    is(join(":", @suites), "TLS_AES_128_GCM_SHA256",
       "only the configured TLSv1.3 ciphersuite is listed");
    with({ exit_checker => sub { return shift == 1; } },
        sub {
            ok(run(app(["openssl", "ciphers", "-ciphersuites",
                        "NOSUCHSUITE"])),
               "an unknown TLSv1.3 ciphersuite is rejected");
        });
};
