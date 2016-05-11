#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;

my $test_name = "test_networking";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS|MSWin32)$/;

plan skip_all => "$test_name needs the dynamic engine feature enabled"
    if disabled("engine") || disabled("dynamic-engine");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

$ENV{OPENSSL_ia32cap} = '~0x200000200000000';

my $proxy = TLSProxy::Proxy->new(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

plan tests => 2;

#Test 1: Try IPv4
$proxy->clear();
$proxy->serverflags("-4");
$proxy->clientflags("-4");
$proxy->server_addr("127.0.0.1");
$proxy->proxy_addr("127.0.0.1");
ok(check_connection(), "Trying IPv4");

 SKIP: {
     skip "No IPv6 support", 1 unless $proxy->supports_IPv6();

     #Test 2: Try IPv6
     $proxy->clear();
     $proxy->serverflags("-6");
     $proxy->clientflags("-6");
     $proxy->server_addr("[::1]");
     $proxy->proxy_addr("[::1]");
     ok(check_connection(), "Trying IPv6");
}

sub check_connection
{
    eval { $proxy->start(); };

    if ($@ ne "") {
	print STDERR "Proxy connection failed: $@\n";
	return 0;
    }

    1;
}
