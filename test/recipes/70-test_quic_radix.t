#! /usr/bin/env perl
# Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test qw/:DEFAULT result_file result_dir srctop_file data_file/;
use OpenSSL::Test::Utils;
use File::Path 2.00 qw(rmtree);

sub diagnose_failure {
    my ($log, $max_bytes) = @_;
    my $fh;

    diag("Full stderr: $log");
    if (!open($fh, "<", $log)) {
        diag("Could not open stderr log: $!");
        return;
    }

    binmode($fh);
    my $size = -s $fh;
    if (!defined($size)) {
        diag("Could not determine stderr log size: $!");
        close($fh);
        return;
    }

    my $offset = $size > $max_bytes ? $size - $max_bytes : 0;
    if (!seek($fh, $offset, 0)) {
        diag("Could not seek in stderr log: $!");
        close($fh);
        return;
    }

    # Do not start the diagnostic output with a truncated line.
    scalar <$fh> if $offset > 0;

    diag("Stderr tail (up to " . ($max_bytes / 1024) . " KiB):");
    while (my $line = <$fh>) {
        $line =~ s/\r?\n\z//;
        diag($line);
    }
    close($fh);
}

setup("test_quic_radix");

plan skip_all => "QUIC protocol is not supported by this OpenSSL build"
    if disabled('quic');

plan tests => 2;

# Keep the test's multi-megabyte diagnostics out of the TAP pipe.
my $redirect = $ENV{HARNESS_ACTIVE} && !$ENV{HARNESS_VERBOSE};
my $stderr_log = result_file("quic_radix_test.log");
my $result = run(test(["quic_radix_test",
                       srctop_file("test", "certs", "servercert.pem"),
                       srctop_file("test", "certs", "serverkey.pem")],
                      $redirect ? (stderr => $stderr_log) : ()));

diagnose_failure($stderr_log, 32 * 1024) if !$result && $redirect;
ok($result, "running QUIC RADIX tests");

SKIP: {
    skip "no qlog", 1 if disabled('qlog');
    skip "not running CI tests", 1 unless $ENV{OSSL_RUN_CI_TESTS};

    subtest "generate and check qlog output" => sub {
        plan tests => 2;

        my $qlog_output = result_dir("qlog-output");
        rmtree($qlog_output, { safe => 1 });
        mkdir($qlog_output);
        local $ENV{QLOGDIR} = $qlog_output;
        local $ENV{OSSL_QFILTER} = "* -quic:unknown_event quic:another_unknown_event";

        ok(run(test(["quic_radix_test",
                     srctop_file("test", "certs", "servercert.pem"),
                     srctop_file("test", "certs", "serverkey.pem")])),
               "running quic_radix_test to contribute qlog output");

        ok(run(cmd([data_file("verify-qlog.py")], exe_shell => "python3")),
               "running qlog verification script");
    };
}
