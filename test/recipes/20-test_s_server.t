#! /usr/bin/env perl
# Copyright 2020-2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT with srctop_file data_file/;
use OpenSSL::Test::Utils;

setup("test_s_server");

plan tests => 1;

my @certs = qw(test certs);

subtest "HTTP request against s_server -WWW" => sub {

    # Create file for server to serve.
    my $expected = "This is a test.\n";
    my $f;
    open($f, '>', "test.txt") or die "cannot open file";
    print $f $expected;
    close $f;

    # Start up the server.
    my $server_pid =
        run_background(app(["openssl", "s_server",
                            "-cert", srctop_file(@certs, "ee-cert.pem"),
                            "-key", srctop_file(@certs, "ee-key.pem"),
                            "-WWW"]));

    # Test that we can make a simple request against the server.
    my @data = run(app(["openssl", "s_client", "-quiet",
                        "-connect", "127.0.0.1:4433"],
                       stdin => data_file("http-in.txt")),
                   capture => 1);

    ok($data[0] =~ qr/^HTTP\/1.0 200 /, "HTTP server serves 200");
    ok($data[3] =~ qr/$expected/, "HTTP server serves file content");

    # Tear down server.
    kill_background($server_pid);
};
