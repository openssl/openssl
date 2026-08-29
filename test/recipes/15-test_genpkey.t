#! /usr/bin/env perl
# Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT with app_fails slurp_file/;
use OpenSSL::Test::Utils;

setup("test_genpkey");

my @algs = ();
push @algs, qw(RSA) unless disabled("rsa");
push @algs, qw(DSA) unless disabled("dsa");
push @algs, qw(DH DHX) unless disabled("dh");
push @algs, qw(EC) unless disabled("ec");
push @algs, qw(X25519 X448) unless disabled("ecx");
push @algs, qw(SM2) unless disabled("sm2");

plan tests => scalar(@algs) + 4;

foreach (@algs) {
    my $alg = $_;

    ok(run(app([ 'openssl', 'genpkey', '-algorithm', $alg, '-help'])),
       "show genpkey pkeyopt values for $alg");
}

SKIP: {
    skip "RSA is not supported by this OpenSSL build", 1 if disabled("rsa");

    subtest "genpkey with a cipher encrypts the private key" => sub {
        plan tests => 3;

        my $key = "genpkey_enc.pem";

        ok(run(app(['openssl', 'genpkey', '-algorithm', 'RSA',
                    '-pkeyopt', 'rsa_keygen_bits:512',
                    '-aes256', '-pass', 'pass:secret', '-out', $key])),
           "Generate an AES-256 encrypted RSA key");
        ok(run(app(['openssl', 'pkey', '-in', $key,
                    '-passin', 'pass:secret', '-noout'])),
           "Read the encrypted key back with the correct passphrase");
        # A wrong passphrase must not decrypt the key.
        with({ exit_checker => sub { return shift == 1; } },
            sub {
                ok(run(app(['openssl', 'pkey', '-in', $key,
                            '-passin', 'pass:wrong', '-noout'])),
                   "Reading with a wrong passphrase fails");
            });
    };
}

SKIP: {
    skip "DSA is not supported by this OpenSSL build", 1 if disabled("dsa");

    # A cipher only encrypts a private key, so it is rejected with -genparam.
    with({ exit_checker => sub { return shift == 1; } },
        sub {
            ok(run(app(['openssl', 'genpkey', '-genparam', '-algorithm', 'DSA',
                        '-pkeyopt', 'dsa_paramgen_bits:512', '-aes256'])),
               "Cannot use a cipher with -genparam");
        });
}

subtest "genpkey error cases" => sub {
    plan tests => 20;

    app_fails('genpkey', "no algorithm or parameter file should fail",
              qr/Use -help for summary/);
    app_fails('genpkey', "extra positional argument should fail",
              qr/Extra option: "extra"/,
              '-algorithm', 'RSA', 'extra');
    app_fails('genpkey', "invalid output format should fail",
              qr/Invalid format "BAD" for option -outform/,
              '-outform', 'BAD', '-algorithm', 'RSA');
    app_fails('genpkey', "parameter file with -genparam should fail",
              qr/Use -help for summary/,
              '-genparam', '-paramfile', 'dsagen.pem');
    app_fails('genpkey', "unknown algorithm should fail",
              qr/Error initializing FOO context/,
              '-algorithm', 'FOO');
    app_fails('genpkey', "unknown key option should fail",
              qr/Error setting bad:1 parameter/,
              '-algorithm', 'RSA', '-pkeyopt', 'bad:1');
    app_fails('genpkey', "unknown cipher option should fail",
              qr/Unknown option or cipher: badcipher/,
              '-algorithm', 'RSA', '-badcipher');
    app_fails('genpkey', "invalid pass argument should fail",
              qr/Error getting password/,
              '-algorithm', 'RSA', '-pass', 'bad:secret');
    app_fails('genpkey', "nonexistent parameter file should fail",
              qr/Can't open parameter file/,
              '-paramfile', 'nonexistent.pem');

    my $garbage = "garbage.pem";
    open(my $fh, '>', $garbage) or die "Cannot write $garbage: $!";
    print $fh "not a valid params file\n";
    close($fh);
    app_fails('genpkey', "garbage parameter file should fail",
              qr/Error reading parameter file/,
              '-paramfile', $garbage);
};

subtest "genpkey verbose mode" => sub {
    plan tests => 4;

    my $stderr_file = "genpkey_verbose.txt";

    ok(run(app(['openssl', 'genpkey', '-verbose', '-algorithm', 'RSA',
                '-pkeyopt', 'rsa_keygen_bits:2048',
                '-out', 'genpkey-verbose.pem'],
               stderr => $stderr_file)),
       "genpkey -verbose generates a key");
    my $err = slurp_file($stderr_file);
    ok($err =~ qr/Generating RSA key/,
       "-verbose reports the key generation");

    ok(run(app(['openssl', 'genpkey', '-quiet', '-algorithm', 'RSA',
                '-pkeyopt', 'rsa_keygen_bits:2048',
                '-out', 'genpkey-quiet.pem'],
               stderr => $stderr_file)),
       "genpkey -quiet generates a key");
    $err = slurp_file($stderr_file);
    ok($err !~ qr/Generating RSA key/,
       "-quiet does not report the key generation");
    unlink($stderr_file) if -f $stderr_file;
};
