#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT bldtop_file srctop_file cmdstr/;

setup("test_external");

plan skip_all => "No external tests in this configuration"
    if disabled("external-tests");

if (!$ENV{BORING_RUNNER_DIR}) {
    plan skip_all => "No external tests have been detected";
}

plan tests => 1;

indir $ENV{BORING_RUNNER_DIR} => sub {
    ok(filter_run(cmd(["go", "test", "-shim-path",
                      bldtop_file("test", "ossl_shim", "ossl_shim"),
                      "-shim-config",
                      srctop_file("test", "ossl_shim", "ossl_config.json"),
                      "-pipe", "-allow-unimplemented"])),
        "running external tests");
}, create => 0, cleanup => 0;

# Filter the output so that the "ok" printed by go test doesn't confuse
# Test::More. Without that it thinks there has been one more test run than was
# planned
sub filter_run {
    my $cmd = cmdstr(shift);
    open(PIPE, "-|", $cmd);
    while(<PIPE>) {
        print STDOUT "go test: ", $_;
    }
    close PIPE;
}
