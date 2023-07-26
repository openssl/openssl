#! /usr/bin/env perl
# Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use IPC::Open2;
use OpenSSL::Test qw/:DEFAULT srctop_file bldtop_file/;
use OpenSSL::Test::Utils;

setup("test_ocsp_check");

plan skip_all => "OCSP is not supported by this OpenSSL build"
    if disabled("ocsp");

plan tests => 2;

my $shlib_wrap = bldtop_file("util", "shlib_wrap.sh");
my $apps_openssl = bldtop_file("apps", "openssl");
my $ca = srctop_file("test", "recipes", "80-test_ocsp_check_data", "ca.pem");
my $ca_key = srctop_file("test", "recipes", "80-test_ocsp_check_data", "ca.key");
my $ocsp = srctop_file("test", "recipes", "80-test_ocsp_check_data", "ocsp.pem");
my $ocsp_key = srctop_file("test", "recipes", "80-test_ocsp_check_data", "ocsp.key");
my $server = srctop_file("test", "recipes", "80-test_ocsp_check_data", "server.pem");
my $server_key = srctop_file("test", "recipes", "80-test_ocsp_check_data", "server.key");
my $index;
my $ocsp_port = 9999;
my $https_port = 8443;
# 20 July 2023 so we don't get certificate expiry errors.
my @check_time=("-attime", "1689811200");

sub run_test {
  my $id = shift;
  my $connect_good = 0;

  if ($id == 0) {
    $index = srctop_file("test", "recipes", "80-test_ocsp_check_data", "index-valid.txt");
  }
  if ($id == 1) {
    $index = srctop_file("test", "recipes", "80-test_ocsp_check_data", "index-revoked.txt");
  }
  # OCSP responder
  my @o_cmd = ("ocsp", "-index", $index, "-port", "$ocsp_port", "-rsigner", $ocsp, "-rkey", $ocsp_key, "-CA", $ca, "-nrequest", "1", @check_time);
  # server
  my @s_cmd = ("s_server", "-www", "-status_url", "http://127.0.0.1:$ocsp_port", "-accept", "$https_port", "-cert", $server, "-key", $server_key, "-state", "-CAfile", $ca, "-naccept", "1", @check_time);
  # client
  my @c_cmd = ("s_client", "-connect", ":$https_port", "-CAfile", $ca, "-status", "-verify_return_error", "-strict", @check_time);

  # Run the OCSP responder
  my $o_pid = open2(my $o_out, my $o_in, $shlib_wrap, $apps_openssl, @o_cmd);

  # Start up the server
  my $s_pid = open2(my $s_out, my $s_in, $shlib_wrap, $apps_openssl, @s_cmd);
  while (<$s_out>) {
    chomp;
    if (/^ACCEPT$/) {
      print "Server ready\n";
      last;
    }
  }

  # Start up the client
  my $c_pid = open2(my $c_out, my $c_in, $shlib_wrap, $apps_openssl, @c_cmd);
  if ($id == 0) {
      # Do the "GET", which will cause the client to finish
      print $c_in "GET /\r\n";
  }

  waitpid($c_pid, 0);
  waitpid($s_pid, 0);
  waitpid($o_pid, 0);

  # Check the client output
  while (<$c_out>) {
    chomp;
    if ($id == 0) {
      $connect_good = 1 if /^Content-type: text/;
    }
    if ($id == 1) {
      $connect_good = 1 if /^revoked certificate found in OCSP response/;
    }
  }
  print STDERR "Connection failed, expected string not found\n" if ! ok($connect_good);
}

for my $index (0..1) {
  run_test($index)
}