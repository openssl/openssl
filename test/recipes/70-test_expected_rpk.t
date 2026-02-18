#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;
use Cwd qw(abs_path);

my $test_name = "test_expected_rpk";
setup($test_name);

$ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("test"));

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the module feature enabled"
    if disabled("module");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan tests => 2;

my $proxy = TLSProxy::Proxy->new(
    sub { return; },
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

SKIP: {
    skip "No TLS 1.2 support in this OpenSSL build", 1 if disabled("tls1_2");
    $proxy->clear();
    $proxy->clientflags("-tls1_2 -verify 1 -verify_return_error -enable_client_rpk".
                        " -cert ". srctop_file("apps", "server.pem").
                        " -expected-rpks ". srctop_file("apps", "server.pem"));
    $proxy->serverflags("-tls1_2 -Verify 1 -verify_return_error -enable_server_rpk".
                        " -expected-rpks ". srctop_file("apps", "server.pem"));

    $proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
    ok(TLSProxy::Message->success, "Verified TLS 1.2 mutual RPK");
}

SKIP: {
    skip "No TLS 1.3 support in this OpenSSL build", 1 if disabled("tls1_3");
    $proxy->clear();
    $proxy->clientflags("-tls1_3 -verify 1 -verify_return_error -enable_client_rpk".
                        " -cert ". srctop_file("apps", "server.pem").
                        " -expected-rpks ". srctop_file("apps", "server.pem"));
    $proxy->serverflags("-tls1_3 -Verify 1 -verify_return_error -enable_server_rpk".
                        " -expected-rpks ". srctop_file("apps", "server.pem"));
    $proxy->start();
    ok(TLSProxy::Message->success, "Verified TLS 1.3 mutual RPK");
}
