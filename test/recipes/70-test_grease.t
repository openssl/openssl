#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;
use Cwd qw(abs_path);

setup("test_grease");

plan skip_all => "s_client needs socket and TLS support"
    if disabled("sock") || disabled("tls");

my @invalid = ("unknown", "", ",groups", "groups,", "groups,,versions",
               "groups,unknown", "ALL", "1", "0x3f", " groups", "groups ",
               "key_share", "key_share,versions");
my @wire = (
    ["", [0, 0, 0, 0, 0, 0]],
    ["-grease", [1, 1, 1, 1, 1, 2]],
    ["-grease_fields all", [1, 1, 1, 1, 1, 2]],
    ["-grease_fields cipher_suites", [1, 0, 0, 0, 0, 0]],
    ["-grease_fields groups", [0, 1, 0, 0, 0, 0]],
    ["-grease_fields groups,key_share", [0, 1, 1, 0, 0, 0]],
    ["-grease_fields versions", [0, 0, 0, 1, 0, 0]],
    ["-grease_fields sigalgs", [0, 0, 0, 0, 1, 0]],
    ["-grease_fields extensions", [0, 0, 0, 0, 0, 2]],
    ["-grease_fields cipher_suites,groups,key_share,versions,sigalgs,extensions",
     [1, 1, 1, 1, 1, 2]],
    ["-grease_fields versions -grease_fields cipher_suites", [1, 0, 0, 0, 0, 0]],
    ["-grease_fields versions -grease", [0, 0, 0, 1, 0, 0]],
    ["-grease -grease_fields versions", [0, 0, 0, 1, 0, 0]],
);

plan tests => scalar(@invalid) + scalar(@wire);

foreach my $fields (@invalid) {
    subtest "reject '$fields'" => sub {
        plan tests => 2;
        ok(!run(app(["openssl", "s_client", "-grease_fields", $fields,
                     "-connect", "127.0.0.1:0"], stdin => undef,
                    stdout => "client.out", stderr => "client.err")),
           "invalid selection fails");
        open my $err, "<", "client.err" or die "Cannot read client.err: $!";
        my $text = do { local $/; <$err> };
        close $err;
        like($text, qr/Invalid -grease_fields (?:list|mask)/,
             "failure identifies the GREASE option");
    };
}

SKIP: {
    skip "TLSProxy needs modules, EC and TLS 1.3 and cannot run on VMS",
        scalar(@wire)
        if $^O eq "VMS" || disabled("module") || disabled("ec")
            || disabled("tls1_3");

    local $ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("test"));
    my $proxy = TLSProxy::Proxy->new(
        undef, cmdstr(app(["openssl"]), display => 1),
        srctop_file("apps", "server.pem"),
        (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE}), have_IPv6());

    foreach my $case (@wire) {
        my ($flags, $expected) = @$case;
        subtest "ClientHello '$flags'" => sub {
            plan tests => 3;
            $proxy->clear();
            $proxy->clientflags("-tls1_3 -groups P-256 $flags");
            $proxy->serverflags("-tls1_3 -groups P-256");
            $proxy->start();
            ok(TLSProxy::Message->success(), "handshake completes");
            my ($hello) = grep {
                $_->mt() == TLSProxy::Message::MT_CLIENT_HELLO
            } @{$proxy->message_list()};
            ok(defined($hello), "ClientHello captured");
            my @actual = defined($hello) ? grease_fields($hello) : ();
            is_deeply(\@actual, $expected,
                      "only selected fields contain GREASE");
        };
    }
}

sub is_grease {
    my $value = shift;
    return ($value & 0x0f0f) == 0x0a0a
        && ($value >> 8) == ($value & 0xff);
}

# Count GREASE in a length-prefixed vector of two-byte values.
sub vector_grease {
    my ($data, $prefix) = @_;
    return 0 unless defined($data);
    die "Truncated vector" if length($data) < $prefix;
    my $len = unpack($prefix == 1 ? "C" : "n", $data);
    die "Invalid vector length" if $len != length($data) - $prefix || $len % 2;
    return scalar grep { is_grease($_) } unpack("n*", substr($data, $prefix));
}

sub grease_fields {
    my $hello = shift;
    my $exts = $hello->extension_data();
    my $shares = $exts->{TLSProxy::Message::EXT_KEY_SHARE};
    my $key_grease = 0;

    if (defined($shares)) {
        die "Truncated key shares" if length($shares) < 2;
        die "Invalid key share vector length"
            if unpack("n", $shares) != length($shares) - 2;
        for (my $offset = 2; $offset < length($shares);) {
            die "Truncated key share" if length($shares) - $offset < 4;
            my ($group, $len) = unpack("nn", substr($shares, $offset, 4));
            $offset += 4 + $len;
            die "Invalid key share length" if $offset > length($shares);
            $key_grease++ if is_grease($group);
        }
    }
    return (scalar(grep { is_grease($_) } @{$hello->ciphersuites()}),
            vector_grease($exts->{TLSProxy::Message::EXT_SUPPORTED_GROUPS}, 2),
            $key_grease,
            vector_grease($exts->{TLSProxy::Message::EXT_SUPPORTED_VERSIONS}, 1),
            vector_grease($exts->{TLSProxy::Message::EXT_SIG_ALGS}, 2),
            scalar(grep { is_grease($_) } keys %$exts));
}
