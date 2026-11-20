#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT srctop_file result_file);
use OpenSSL::Test::Utils;

setup("test_secret_check_conf");

plan skip_all => "This test requires ML-DSA"
    if disabled("ml-dsa");

plan tests => 5;

# An ML-DSA-44 key whose seed is all zero bytes
my $key = srctop_file("test", "testmldsa44.pem");

# Writes a configuration whose secret_check section holds $body
sub write_conf {
    my ($name, $body) = @_;
    my $file = result_file($name);
    my $fh;

    open($fh, '>', $file) or return undef;
    print $fh "config_diagnostics = 1\n",
              "openssl_conf = openssl_init\n\n",
              "[openssl_init]\n",
              "secret_check = secret_check_sect\n\n",
              "[secret_check_sect]\n",
              $body;
    close($fh) or return undef;
    return $file;
}

sub load_key {
    my $conf = shift;

    $ENV{OPENSSL_CONF} = $conf;
    return run(app(['openssl', 'pkey', '-in', $key, '-noout']));
}

my $off = write_conf("secret_check_off.cnf", "enabled = no\n");
my $on = write_conf("secret_check_on.cnf", "enabled = yes\n");
my $badname = write_conf("secret_check_badname.cnf", "enable = no\n");
my $badvalue = write_conf("secret_check_badvalue.cnf", "enabled = maybe\n");

ok(defined $off && defined $on && defined $badname && defined $badvalue,
   "Write the configuration files");
ok(load_key($off), "enabled = no accepts the key");
ok(!load_key($on), "enabled = yes rejects the key");
ok(!load_key($badname), "An unknown name is a configuration error");
ok(!load_key($badvalue), "An unknown value is a configuration error");
