#! /usr/bin/env perl
# Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT result_dir with/;
use OpenSSL::Test::Utils;

setup("test_rand_config");

my @rand_tests = (
    { drbg => 'HASH-DRBG',
      digest => 'SHA2-512/256',
      properties => '',
      expected => ["HASH-DRBG", "digest: 'SHA2-512/256'"],
      desc => 'HASH-DRBG SHA2-512/256' },

    { drbg => 'HASH-DRBG',
      digest => 'SHA3-256',
      properties => '',
      expected => ["HASH-DRBG", "digest: 'SHA3-512'"],
      desc => 'HASH-DRBG SHA3/512' },

    { drbg => 'HMAC-DRBG',
      digest => 'SHA3-256',
      properties => '',
      expected => ["HMAC-DRBG", "mac: HMAC", "digest: 'SHA3-256'"],
      desc => 'HMAC-DRBG SHA3/256' },

    { cipher => 'AES-128-CTR',
      expected => ["CTR-DRBG", "cipher: 'AES-128-CTR'"],
      desc => 'CTR-DRBG AES-128 no DRBG' },
    { expected => ["CTR-DRBG", "cipher: 'AES-256-CTR'"],
      desc => 'CTR-DRBG AES-256 defaults' },
);

my @aria_tests = (
    { drbg => 'CTR-DRBG',
      cipher => 'ARIA-128-CTR',
      properties => '',
      expected => ["CTR-DRBG", "cipher: 'ARIA-128-CTR'"],
      desc => 'CTR-DRBG ARIA-128' },

    { drbg => 'CTR-DRBG',
      cipher => 'ARIA-128-CTR',
      properties => '',
      expected => ["CTR-DRBG", "cipher: 'ARIA-128-CTR'"],
      desc => 'CTR-DRBG ARIA-256' },
);

push @rand_tests, @aria_tests unless disabled("aria");

# Configured seed sources must be honoured: an available one is used and
# an unavailable one is an error rather than a silent fallback to the
# operating system entropy sources.  Not applicable to enable-fips-jitter
# builds, which hard-wire the JITTER seed source.
my $rand_seed_none =
    grep { $_ eq 'OPENSSL_RAND_SEED_NONE' }
        @{ config('openssl_feature_defines') // [] };
my @seed_tests;
if (disabled("fips-jitter")) {
    push @seed_tests,
        { seed => 'SEED-SRC',
          expected_ok => 1,
          desc => 'configured SEED-SRC seed source works' }
        unless $rand_seed_none;
    push @seed_tests,
        { seed => 'SEED-SRC',
          strict => 'yes',
          expected_ok => 1,
          desc => 'strictly configured SEED-SRC seed source works' }
        unless $rand_seed_none;
    push @seed_tests,
        { seed => 'NONEXISTENT-SEED-SOURCE',
          expected_ok => 0,
          desc => 'unavailable configured seed source fails, no fallback' };
    push @seed_tests,
        { seed => 'HASH-DRBG',
          strict => 'yes',
          args => ['-hex', '1'],
          expected_exit => 1,
          stderr_re => qr/error:1200006E:/,
          desc => 'recursive strict seed source fails cleanly' };
}

plan tests => scalar @rand_tests * 2 + scalar @seed_tests
    + scalar grep { defined $_->{stderr_re} } @seed_tests;

my $contents =<<'CONFIGEND';
openssl_conf = openssl_init

[openssl_init]
random = random_section

[random_section]
CONFIGEND

foreach (@rand_tests) {
    my $tmpfile = 'rand_config.cfg';
    open(my $cfg, '>', $tmpfile) or die "Could not open file";
    print $cfg $contents;
    if ($_->{drbg}) {
        print $cfg "random = $_->{drbg}\n";
    }
    if ($_->{cipher}) {
        print $cfg "cipher = $_->{cipher}\n";
    }
    if ($_->{digest}) {
        print $cfg "digest = $_->{digest}\n"
    }
    close $cfg;

    $ENV{OPENSSL_CONF} = $tmpfile;

    ok(comparelines($_->{expected}), $_->{desc});
    # Also check that instantiating the drbg works
    my $result_dir = result_dir();
    ok(run(app(["openssl", "rand", "-writerand", "$result_dir/$tmpfile.bin"])));
}

foreach (@seed_tests) {
    my $tmpfile = 'rand_seed_config.cfg';
    open(my $cfg, '>', $tmpfile) or die "Could not open file";
    print $cfg $contents;
    print $cfg "seed = $_->{seed}\n";
    print $cfg "seed_strict = $_->{strict}\n" if defined $_->{strict};
    close $cfg;

    $ENV{OPENSSL_CONF} = $tmpfile;

    my @args = @{ $_->{args} // ['-hex', '16'] };
    if (defined $_->{expected_exit}) {
        my $expected_exit = $_->{expected_exit};
        my $stderr_file = 'rand_seed_config.err';

        with({ exit_checker => sub { return shift == $expected_exit; } },
            sub {
                ok(run(app(["openssl", "rand", @args],
                           stderr => $stderr_file)), $_->{desc});
            });
        if (defined $_->{stderr_re}) {
            open(my $err, '<', $stderr_file)
                or die "Could not open error output";
            my $error = do { local $/; <$err> };
            close($err);
            like($error, $_->{stderr_re},
                 "$_->{desc} reports a RAND error");
        }
        unlink($stderr_file);
    } else {
        my $ok = run(app(["openssl", "rand", @args]));
        ok(!$ok == !$_->{expected_ok}, $_->{desc});
    }
}

# Check that the stdout output contains the expected values.
sub comparelines {
    my @lines = run(app(["openssl", "list", "--random-instances"]),
                    capture => 1);

    foreach (@_) {
        if ( !grep( /$_/, @lines ) ) {
            print "Cannot find: $_\n";
            return 0;
        }
    }
    return 1;
}
