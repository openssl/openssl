#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT data_file bldtop_dir srctop_dir cmdstr/;

setup("test_external_ech_nss");

plan skip_all => "No external tests in this configuration"
    if disabled("external-tests");
plan skip_all => "External ECH tests not available on Windows or VMS"
    if $^O =~ /^(VMS|MSWin32)$/;
    #plan skip_all => "External ECH tests only available in a shared build"
    #if disabled("shared");
plan skip_all => "External ECH tests not supported in out of tree builds"
    if bldtop_dir() ne srctop_dir();

# There is an issue with running the NSS server test in the CI setup. The
# NSS server test uses the NSS selfserv test server, which, when ECH is
# enabled generates an ephemeral ECHConfig and private key and prints the
# base64 encoded ECHConfigList to stdout, which we then collect and feed
# into s_client for the ECH test. When run locally this requires setting
# `stdbuf -o0` on the command line to avoid buffering, but that setting
# seems not to work in the CI environment. For now, we therefore omit the
# NSS server test when running in the CI environment, which is ok as we
# have another test checking ECH between s_client and the BoringSSL test
# server. As a result, we need to set `OSSL_RUN_CI_TESTS` in the CI
# environment to signal that the NSS server test is not to be run.
if (defined ($ENV{OSSL_RUN_CI_TESTS})) {
    plan tests => 1;
} else {
    plan tests => 2;
}

ok(run(cmd(["sh", data_file("ech_nss_external.sh")])),
   "running ECH client external NSS tests");

if (! defined ($ENV{OSSL_RUN_CI_TESTS})) {
    ok(run(cmd(["sh", data_file("ech_nss_server_external.sh")])),
    "running ECH server external NSS tests");
}
