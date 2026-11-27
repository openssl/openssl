#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You may obtain a copy
# of the License at https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Spec::Functions qw(devnull);
use IPC::Open2;
use OpenSSL::Test qw/:DEFAULT srctop_file bldtop_file/;
use OpenSSL::Test::Utils;

setup("test_s_server_pass");

plan skip_all => "test_s_server_pass needs sock enabled"
    if disabled("sock");
plan skip_all => "test_s_server_pass requires TLS enabled"
    if alldisabled(available_protocols("tls"));
# With TLS 1.3 enabled but no ec or dh, there are no key exchange
# groups at all, so no TLS connection can be established
plan skip_all => "test_s_server_pass requires TLS key exchange groups"
    if !disabled("tls1_3") && alldisabled(qw(ec dh));
plan skip_all => "test_s_server_pass does not run on Windows nor VMS"
    if $^O =~ /^(VMS|MSWin32|msys)$/;

plan tests => 8;

my $shlib_wrap = bldtop_file("util", "shlib_wrap.sh");
my $apps_openssl = bldtop_file("apps", "openssl");
my $cert = srctop_file("apps", "server.pem");
my $null = devnull();

# Build a file holding the server key in traditional encrypted form,
# followed by the server certificate -- the layout that triggered
# https://github.com/openssl/openssl/issues/23839
my $combined = "server-keycert.pem";
my $certonly = "server-cert.pem";

ok(run(app(["openssl", "rsa", "-in", $cert,
            "-traditional", "-aes128", "-passout", "pass:password",
            "-out", $combined]))
   && run(app(["openssl", "x509", "-in", $cert, "-out", $certonly]))
   && do {
        open my $out, '>>', $combined or die $!;
        open my $in, '<', $certonly or die $!;
        print {$out} (<$in>);
        close $in;
        close $out;
        1;
      },
   "building combined cert+key file");

# Run s_server with the given arguments; return whether it started,
# whether it served a client, and whether it prompted for a pass phrase.
sub run_s_server {
    my (@args) = @_;
    my $serr = "s_server-err.txt";
    my $spid = open(my $sout, "-|",
        "\"$shlib_wrap\" \"$apps_openssl\" s_server -accept :0 -www"
        . " -naccept 1 @args < $null 2> $serr");

    my $port = 0;
    while (<$sout>) {
        chomp;
        if (/^ACCEPT\s.*:(\d+)$/) {
            $port = $1;
            last;
        }
    }

    my $connect_good = 0;
    if ($port) {
        print STDERR "Port: $port\n";
        # Start up the client and do the "GET", which will cause the
        # client to finish
        my $cpid = open2(my $cout, my $cin, $shlib_wrap, $apps_openssl,
                         "s_client", "-connect", ":$port");
        print $cin "GET /\r\n";

        # Read the client output while it runs; only reading it after
        # waitpid risks a deadlock on a full pipe.
        while (<$cout>) {
            chomp;
            $connect_good = 1 if /^Content-type: text/;
        }
        waitpid($cpid, 0);
    }
    waitpid($spid, 0);

    open my $efh, '<', $serr or die $!;
    my @serrs = <$efh>;
    close $efh;
    my $prompted = grep (/Enter pass phrase/, @serrs);

    return ($port, $connect_good, $prompted);
}

# Scenario 1: the key is loaded from the combined file, so -pass is
# needed for the key itself; looking for DH parameters in the same file
# must not prompt for a pass phrase.
{
    my ($port, $connect_good, $prompted) =
        run_s_server("-cert", $combined, "-pass", "pass:password");
    ok($port, "s_server started with combined cert+key file, -pass given");
    ok($connect_good, "client connection served");
    ok($prompted == 0, "no pass phrase prompt from s_server");
}

# Scenario 2: the key is loaded from a separate unencrypted file and no
# password is given at all; looking for DH parameters in the combined
# file must skip the encrypted key, not try to decrypt it.
ok(run(app(["openssl", "rsa", "-in", $cert, "-out", "server-key.pem"])),
   "building separate key file");
{
    my ($port, $connect_good, $prompted) =
        run_s_server("-cert", $combined, "-key", "server-key.pem");
    ok($port, "s_server started with separate key, no -pass");
    ok($connect_good, "client connection served");
    ok($prompted == 0, "no pass phrase prompt from s_server");
}
