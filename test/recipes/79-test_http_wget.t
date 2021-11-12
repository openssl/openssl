#! /usr/bin/env perl
# Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT data_file bldtop_dir srctop_dir cmdstr/;

setup("test_http_wget");

plan skip_all => "HTTP test with real server not available on Windows or VMS"
    if $^O =~ /^(VMS|MSWin32)$/;
plan skip_all => "sockets disabled" if disabled("sock");

plan tests => 2;

# using wget because it also uses http_proxy, https_proxy, and no_proxy
my $check_reachable = "wget -O /dev/null 2>/dev/null --no-verbose --tries=1 --max-redirect=0 --timeout=2";

foreach my $server ("http://httpbin.org", "https://httpbin.org") {
  SKIP: {
      if ($server =~ m/https:/) {
          skip "No TLS/SSL protocols are supported by this OpenSSL build", 1
              if alldisabled(grep { $_ ne "ssl3" } available_protocols("tls"));
          skip "No EC supported by this OpenSSL build, needed for TLS", 1
              if disabled("ec");
      }
      system("$check_reachable $server");
      skip "HTTP server $server not reachable", 1 if $? >> 8;
      my $url = "$server/get";
      my @lines = run(test(["http_wget_test", $url]), capture => 1);
      my $expected = "httpbin.org";
      is((scalar (grep /$expected/, @lines) > 0 ? 1 : 0), 1);
    }
}
