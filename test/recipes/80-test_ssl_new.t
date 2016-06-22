#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Basename;
use File::Compare qw/compare_text/;
use if $^O ne "VMS", 'File::Glob' => qw/glob/;

use OpenSSL::Test qw/:DEFAULT srctop_dir srctop_file/;
use OpenSSL::Test::Utils qw/disabled alldisabled available_protocols/;

setup("test_ssl_new");

$ENV{TEST_CERTS_DIR} = srctop_dir("test", "certs");

my @conf_srcs =  glob(srctop_file("test", "ssl-tests", "*.conf.in"));
map { s/;.*// } @conf_srcs if $^O eq "VMS";
my @conf_files = map { basename($_) } @conf_srcs;
map { s/\.in// } @conf_files;

# 02-protocol-version.conf test and 05-dtls-protocol-version.conf results
# depend on the configuration of enabled protocols. We only verify generated
# sources in the default configuration.
my $is_default_tls = (disabled("ssl3") && !disabled("tls1") &&
                      !disabled("tls1_1") && !disabled("tls1_2"));

my $is_default_dtls = (!disabled("dtls1") && !disabled("dtls1_2"));

my $no_tls = alldisabled(available_protocols("tls"));
my $no_dtls = alldisabled(available_protocols("dtls"));

my %conf_dependent_tests = (
  "02-protocol-version.conf" => !$is_default_tls,
  "04-client_auth.conf" => !$is_default_tls,
  "05-dtls-protocol-version.conf" => !$is_default_dtls,
);

# Default is $no_tls but some tests have different skip conditions.
my %skip = (
  "05-dtls-protocol-version.conf" => $no_dtls,
);

foreach my $conf (@conf_files) {
    subtest "Test configuration $conf" => sub {
        test_conf($conf,
                  $conf_dependent_tests{$conf} || $^O eq "VMS" ?  0 : 1,
                  $skip{$conf} || $no_tls);
    }
}

# We hard-code the number of tests to double-check that the globbing above
# finds all files as expected.
plan tests => 7;  # = scalar @conf_srcs

sub test_conf {
    plan tests => 3;

    my ($conf, $check_source, $skip) = @_;

    my $conf_file = srctop_file("test", "ssl-tests", $conf);
    my $tmp_file = "${conf}.$$.tmp";
    my $run_test = 1;

  SKIP: {
      # "Test" 1. Generate the source.
      my $input_file = $conf_file . ".in";

      skip 'failure', 2 unless
        ok(run(perltest(["generate_ssl_tests.pl", $input_file],
                        interpreter_args => [ "-I", srctop_dir("test", "testlib")],
                        stdout => $tmp_file)),
           "Getting output from generate_ssl_tests.pl.");

    SKIP: {
        # Test 2. Compare against existing output in test/ssl_tests.conf.
        skip "Skipping generated source test for $conf", 1
          if !$check_source;

        $run_test = is(cmp_text($tmp_file, $conf_file), 0,
                       "Comparing generated sources.");
      }

      # Test 3. Run the test.
      skip "No tests available; skipping tests", 1 if $skip;
      skip "Stale sources; skipping tests", 1 if !$run_test;

      ok(run(test(["ssl_test", $tmp_file])), "running ssl_test $conf");
    }

    unlink glob $tmp_file;
}

sub cmp_text {
    return compare_text(@_, sub {
        $_[0] =~ s/\R//g;
        $_[1] =~ s/\R//g;
        return $_[0] ne $_[1];
    });
}
