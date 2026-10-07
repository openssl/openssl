#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;
use OpenSSL::Test qw(:DEFAULT bldtop_dir srctop_file);

setup("test_mkerr");

plan tests => 13;

indir "fixture" => sub {
    my @mkerr = ($^X, "-I" . bldtop_dir(), srctop_file("util", "mkerr.pl"),
                 "-internal", "-conf", "errors.ec");
    my $initial = "SSL_R_EXISTING:100:custom description\n"
                . "SSL_R_EMPTY:101:\n"
                . "SSL_R_SILENT:102:*\n";

    write_file("errors.ec",
               "L SSL include/openssl/sslerr.h ssl_err.c sslerr.h\nS errors.txt\n");
    write_file("errors.txt", $initial);

    # A build must also handle blank descriptions already in the registry.
    ok(run(cmd([@mkerr, "-emit", "ssl_err.c"], stdout => "before.c")),
       "emit existing reasons");
    my $output = read_file("before.c");
    like($output, qr/SSL_R_EMPTY\),\s*"empty"/,
         "derive an existing blank description");
    like($output, qr/SSL_R_EXISTING\),\s*"custom description"/,
         "preserve an explicit description");
    like($output, qr/SSL_R_SILENT\),\s*""/,
         "preserve an intentionally empty description");
    is(read_file("errors.txt"), $initial, "emission leaves the registry alone");

    mkdir "crypto" or die "Cannot create crypto: $!";
    write_file("crypto/new.c", "ERR_raise(ERR_LIB_SSL, SSL_R_NEW_REASON);\n");
    ok(run(cmd([@mkerr, "-state"])), "record a new reason");
    my $state = read_file("errors.txt");
    like($state, qr/^SSL_R_NEW_REASON:\d+:new reason$/m,
         "record the derived description with the new reason");
    like($state, qr/^SSL_R_EMPTY:101:empty$/m,
         "fill an existing blank description when writing state");
    like($state, qr/^SSL_R_EXISTING:100:custom description$/m,
         "preserve the existing number and description");
    like($state, qr/^SSL_R_SILENT:102:\*$/m,
         "preserve the explicit empty marker in state");
    ok(!-e "ssl_err.c", "state mode doesn't emit C source");

    ok(run(cmd([@mkerr, "-emit", "ssl_err.c"], stdout => "after.c")),
       "emit the updated registry");
    like(read_file("after.c"), qr/SSL_R_NEW_REASON\),\s*"new reason"/,
         "emit the new reason description");
}, create => 1;

sub write_file {
    my ($filename, $text) = @_;

    open my $fh, ">", $filename or die "Cannot write $filename: $!";
    print {$fh} $text or die "Cannot write $filename: $!";
    close $fh or die "Cannot close $filename: $!";
}

sub read_file {
    my ($filename) = @_;

    open my $fh, "<", $filename or die "Cannot read $filename: $!";
    local $/;
    return <$fh>;
}
