#! /usr/bin/env perl
# Copyright 2018-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Spec;
use File::Basename;
use OpenSSL::Test qw/:DEFAULT srctop_file srctop_dir ok_nofips with/;
use OpenSSL::Test::Utils;
use File::Compare qw/compare_text compare/;

setup("test_pkeyutl");

plan tests => 33;

# For the tests below we use the cert itself as the TBS file

SKIP: {
    skip "Skipping tests that require EC, SM2 or SM3", 4
        if disabled("ec") || disabled("sm2") || disabled("sm3") || disabled("x963kdf");

    # SM2
    ok_nofips(run(app(([ 'openssl', 'pkeyutl', '-sign',
                      '-in', srctop_file('test', 'certs', 'sm2.pem'),
                      '-inkey', srctop_file('test', 'certs', 'sm2.key'),
                      '-out', 'sm2.sig', '-rawin',
                      '-digest', 'sm3', '-pkeyopt', 'distid:someid']))),
                      "Sign a piece of data using SM2");
    ok_nofips(run(app(([ 'openssl', 'pkeyutl',
                      '-verify', '-certin',
                      '-in', srctop_file('test', 'certs', 'sm2.pem'),
                      '-inkey', srctop_file('test', 'certs', 'sm2.pem'),
                      '-sigfile', 'sm2.sig', '-rawin',
                      '-digest', 'sm3', '-pkeyopt', 'distid:someid']))),
                      "Verify an SM2 signature against a piece of data");
    ok_nofips(run(app(([ 'openssl', 'pkeyutl', '-encrypt',
                      '-in', srctop_file('test', 'data2.bin'),
                      '-inkey', srctop_file('test', 'certs', 'sm2-pub.key'),
                      '-pubin', '-out', 'sm2.enc']))),
                      "Encrypt a piece of data using SM2");
    ok_nofips(run(app(([ 'openssl', 'pkeyutl', '-decrypt',
                      '-in', 'sm2.enc',
                      '-inkey', srctop_file('test', 'certs', 'sm2.key'),
                      '-out', 'sm2.dat'])))
                      && compare_text('sm2.dat',
                                      srctop_file('test', 'data2.bin')) == 0,
                      "Decrypt a piece of data using SM2");
}

SKIP: {
    skip "Skipping tests that require ECX", 7
        if disabled("ecx");

    # Ed25519
    ok(run(app(([ 'openssl', 'pkeyutl', '-sign', '-in',
                  srctop_file('test', 'certs', 'server-ed25519-cert.pem'),
                  '-inkey', srctop_file('test', 'certs', 'server-ed25519-key.pem'),
                  '-out', 'Ed25519.sig']))),
                  "Sign a piece of data using Ed25519");
    ok(run(app(([ 'openssl', 'pkeyutl', '-verify', '-certin', '-in',
                  srctop_file('test', 'certs', 'server-ed25519-cert.pem'),
                  '-inkey', srctop_file('test', 'certs', 'server-ed25519-cert.pem'),
                  '-sigfile', 'Ed25519.sig']))),
                  "Verify an Ed25519 signature against a piece of data");
    #Check for failure return code
    with({ exit_checker => sub { return shift == 1; } },
        sub {
            ok(run(app(([ 'openssl', 'pkeyutl', '-verifyrecover', '-in', 'Ed25519.sig',
                          '-inkey', srctop_file('test', 'certs', 'server-ed25519-key.pem')]))),
               "Cannot use -verifyrecover with EdDSA");
        });

    # Ed448
    ok(run(app(([ 'openssl', 'pkeyutl', '-sign', '-in',
                  srctop_file('test', 'certs', 'server-ed448-cert.pem'),
                  '-inkey', srctop_file('test', 'certs', 'server-ed448-key.pem'),
                  '-out', 'Ed448.sig', '-rawin']))),
                  "Sign a piece of data using Ed448");
    ok(run(app(([ 'openssl', 'pkeyutl', '-verify', '-certin', '-in',
                  srctop_file('test', 'certs', 'server-ed448-cert.pem'),
                  '-inkey', srctop_file('test', 'certs', 'server-ed448-cert.pem'),
                  '-sigfile', 'Ed448.sig', '-rawin']))),
                  "Verify an Ed448 signature against a piece of data");
    ok(run(app(([ 'openssl', 'pkeyutl', '-sign', '-in',
                  srctop_file('test', 'certs', 'server-ed448-cert.pem'),
                  '-inkey', srctop_file('test', 'certs', 'server-ed448-key.pem'),
                  '-out', 'Ed448.sig']))),
                  "Sign a piece of data using Ed448 -rawin no more needed");
    ok(run(app(([ 'openssl', 'pkeyutl', '-verify', '-certin', '-in',
                  srctop_file('test', 'certs', 'server-ed448-cert.pem'),
                  '-inkey', srctop_file('test', 'certs', 'server-ed448-cert.pem'),
                  '-sigfile', 'Ed448.sig']))),
                  "Verify an Ed448 signature against a piece of data, no -rawin");
}

my $sigfile;
sub tsignverify {
    my $testtext = shift;
    my $privkey = shift;
    my $pubkey = shift;
    my @extraopts = @_;

    my $data_to_sign = srctop_file('test', 'data.bin');
    my $other_data = srctop_file('test', 'data2.bin');
    $sigfile = basename($privkey, '.pem') . '.sig';

    my @args = ();
    plan tests => 5;

    @args = ('openssl', 'pkeyutl', '-sign',
             '-inkey', $privkey,
             '-out', $sigfile,
             '-in', $data_to_sign);
    push(@args, @extraopts);
    ok(run(app([@args])),
       $testtext.": Generating signature");

    @args = ('openssl', 'pkeyutl', '-sign',
             '-inkey', $privkey,
             '-keyform', 'DER',
             '-out', $sigfile,
             '-in', $data_to_sign);
    push(@args, @extraopts);
    #Check for failure return code
    with({ exit_checker => sub { return shift == 1; } },
        sub {
            ok(run(app([@args])),
               $testtext.": Checking that mismatching keyform fails");
        });

    @args = ('openssl', 'pkeyutl', '-verify',
             '-inkey', $privkey,
             '-sigfile', $sigfile,
             '-in', $data_to_sign);
    push(@args, @extraopts);
    ok(run(app([@args])),
       $testtext.": Verify signature with private key");

    @args = ('openssl', 'pkeyutl', '-verify',
             '-keyform', 'PEM',
             '-inkey', $pubkey, '-pubin',
             '-sigfile', $sigfile,
             '-in', $data_to_sign);
    push(@args, @extraopts);
    ok(run(app([@args])),
       $testtext.": Verify signature with public key");

    @args = ('openssl', 'pkeyutl', '-verify',
             '-inkey', $pubkey, '-pubin',
             '-sigfile', $sigfile,
             '-in', $other_data);
    push(@args, @extraopts);
    #Check for failure return code
    with({ exit_checker => sub { return shift == 1; } },
        sub {
            ok(run(app([@args])),
               $testtext.": Expect failure verifying mismatching data");
        });
}

SKIP: {
    skip "RSA is not supported by this OpenSSL build", 3
        if disabled("rsa");

    subtest "RSA CLI signature generation and verification" => sub {
        tsignverify("RSA",
                    srctop_file("test","testrsa.pem"),
                    srctop_file("test","testrsapub.pem"),
                    "-rawin", "-digest", "sha256");
    };

    ok(run(app((['openssl', 'pkeyutl', '-verifyrecover', '-in', $sigfile,
                 '-pubin', '-inkey', srctop_file('test', 'testrsapub.pem')]))),
       "RSA: Verify signature with -verifyrecover");

    subtest "RSA CLI signature and verification with pkeyopt" => sub {
        tsignverify("RSA",
                    srctop_file("test","testrsa.pem"),
                    srctop_file("test","testrsapub.pem"),
                    "-rawin", "-digest", "sha256",
                    "-pkeyopt", "rsa_padding_mode:pss");
    };

    subtest "pkeyutl -rev reverses the input buffer" => sub {
        plan tests => 4;

        my $key = srctop_file("test", "testrsa.pem");
        my $in = "rev_in.bin";
        my $in_rev = "rev_in_reversed.bin";

        # A non-palindromic input, short enough to be signed as a raw digest.
        my $data = "0123456789abcdefghijklmnopqrstuv";
        open(my $fh, '>:raw', $in) or die "cannot create $in: $!";
        print $fh $data;
        close($fh);
        open($fh, '>:raw', $in_rev) or die "cannot create $in_rev: $!";
        print $fh scalar reverse $data;
        close($fh);

        # RSA signing is deterministic, so signing with -rev must match signing
        # the manually reversed input.
        ok(run(app(['openssl', 'pkeyutl', '-sign', '-inkey', $key,
                    '-rev', '-in', $in, '-out', 'rev.sig'])),
           "Sign with -rev");
        ok(run(app(['openssl', 'pkeyutl', '-sign', '-inkey', $key,
                    '-in', $in_rev, '-out', 'rev_manual.sig'])),
           "Sign the manually reversed input");
        is(compare('rev.sig', 'rev_manual.sig'), 0,
           "-rev signature matches signing the reversed input");

        # -rev is rejected together with raw input.
        with({ exit_checker => sub { return shift == 1; } },
            sub {
                ok(run(app(['openssl', 'pkeyutl', '-sign', '-inkey', $key,
                            '-rawin', '-digest', 'sha256', '-rev', '-in', $in])),
                   "-rev cannot be used with -rawin");
            });
    };

}

SKIP: {
    skip "DSA is not supported by this OpenSSL build", 1
        if disabled("dsa");

    subtest "DSA CLI signature generation and verification" => sub {
        tsignverify("DSA",
                    srctop_file("test","testdsa.pem"),
                    srctop_file("test","testdsapub.pem"),
                    "-rawin", "-digest", "sha256");
    };
}

SKIP: {
    skip "ECDSA is not supported by this OpenSSL build", 1
        if disabled("ec");

    subtest "ECDSA CLI signature generation and verification" => sub {
        tsignverify("ECDSA",
                    srctop_file("test","testec-p256.pem"),
                    srctop_file("test","testecpub-p256.pem"),
                    "-rawin", "-digest", "sha256");
    };
}

SKIP: {
    skip "EdDSA is not supported by this OpenSSL build", 7
        if disabled("ecx");

    subtest "pkeyutl -rawin oneshot with file input (mmap or buffer path)" => sub {
        my $data = srctop_file("test", "data.bin");
        my $ed25519_key = srctop_file("test", "tested25519.pem");
        my $ed25519_pub = srctop_file("test", "tested25519pub.pem");
        my $ed448_key = srctop_file("test", "tested448.pem");
        my $ed448_pub = srctop_file("test", "tested448pub.pem");

        plan tests => 4;

        # -in <file> for oneshot: uses mmap on Unix when supported, else buffer+BIO_read
        ok(run(app(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', $ed25519_key,
                    '-in', $data, '-out', 'rawin_file_ed25519.sig'])),
           "Ed25519 -rawin sign from file");
        ok(run(app(['openssl', 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', $ed25519_pub,
                    '-sigfile', 'rawin_file_ed25519.sig', '-in', $data])),
           "Ed25519 -rawin verify from file");
        ok(run(app(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', $ed448_key,
                    '-in', $data, '-out', 'rawin_file_ed448.sig'])),
           "Ed448 -rawin sign from file");
        ok(run(app(['openssl', 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', $ed448_pub,
                    '-sigfile', 'rawin_file_ed448.sig', '-in', $data])),
           "Ed448 -rawin verify from file");
    };

    subtest "pkeyutl -rawin oneshot: no buffer fallback when mmap path fails (Unix)" => sub {
        if ($^O eq 'MSWin32') {
            plan tests => 1;
            ok(1, "Skipped (Unix/mmap only)");
            return;
        }
        plan tests => 2;

        # Use a directory with non-zero st_size so the mmap path is attempted
        # (curdir "." often has st_size 0 on some FS and skips mmap).
        my $ed25519_key = srctop_file("test", "tested25519.pem");
        my $dir = srctop_dir("test");
        my $stderr_file = "pkeyutl_nofallback_err.txt";

        with({ exit_checker => sub { return shift != 0; } },
             sub {
                 ok(run(app(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', $ed25519_key,
                             '-in', $dir, '-out', 'nofallback.sig'],
                            stderr => $stderr_file)),
                    "pkeyutl -rawin with un-mmapable input fails (no fallback)");
             });
        if (open(my $fh, '<', $stderr_file)) {
            my $err = do { local $/; <$fh> };
            close($fh);
            ok($err =~ /Error(?: opening file for memory mapping|: failed to use memory-mapped file)/,
               "stderr mentions mmap failure");
        } else {
            ok(0, "could not read stderr file");
        }
        unlink($stderr_file) if -f $stderr_file;
    };

    subtest "pkeyutl -rawin oneshot with empty file (buffer path, filesize 0)" => sub {
        my $ed25519_key = srctop_file("test", "tested25519.pem");
        my $ed25519_pub = srctop_file("test", "tested25519pub.pem");
        my $empty = "pkeyutl_empty.bin";
        my $sigfile = "rawin_empty_ed25519.sig";
        # Ed25519 is deterministic, so signing the empty message with
        # tested25519.pem always yields this exact signature.
        my $expected_sig =
            "42a443bd375c962f571dbf7402654219655b30c395dee06e" .
            "d2a4a41342686da620889e374807266a3aab535345985c96" .
            "cbb7475c8b0df47968d29fbf3d352e0c";

        plan tests => 3;

        # create a zero-length input file
        open(my $fh, '>', $empty) or die "cannot create $empty: $!";
        close($fh);

        ok(run(app(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', $ed25519_key,
                    '-in', $empty, '-out', $sigfile])),
           "Ed25519 -rawin sign from empty file (filesize 0 buffer path)");
        ok(run(app(['openssl', 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', $ed25519_pub,
                    '-sigfile', $sigfile, '-in', $empty])),
           "Ed25519 -rawin verify from empty file");

        # check the produced signature matches the known reference value
        open(my $sfh, '<:raw', $sigfile) or die "cannot open $sigfile: $!";
        read($sfh, my $sig, -s $sigfile);
        close($sfh);
        is(unpack("H*", $sig), $expected_sig,
           "Ed25519 -rawin empty file signature matches the reference value");

        unlink($empty);
    };

    subtest "Ed25519 CLI signature generation and verification" => sub {
        tsignverify("Ed25519",
                    srctop_file("test","tested25519.pem"),
                    srctop_file("test","tested25519pub.pem"),
                    "-rawin");
    };

    subtest "Ed448 CLI signature generation and verification" => sub {
        tsignverify("Ed448",
                    srctop_file("test","tested448.pem"),
                    srctop_file("test","tested448pub.pem"),
                    "-rawin");
    };

    subtest "Ed25519 CLI signature generation and verification, no -rawin" => sub {
        tsignverify("Ed25519",
                    srctop_file("test","tested25519.pem"),
                    srctop_file("test","tested25519pub.pem"));
    };

    subtest "Ed448 CLI signature generation and verification, no -rawin" => sub {
        tsignverify("Ed448",
                    srctop_file("test","tested448.pem"),
                    srctop_file("test","tested448pub.pem"));
    };
}

#Encap/decap tests
# openssl pkeyutl -encap -pubin -inkey rsa_pub.pem -secret secret.bin -out encap_out.bin
# openssl pkeyutl -decap -inkey rsa_priv.pem -in encap_out.bin -out decap_out.bin
# decap_out is equal to secret
SKIP: {
    skip "RSA is not supported by this OpenSSL build", 7
        if disabled("rsa"); # Note "rsa" isn't (yet?) disablable.

    # Self-compat
    ok(run(app(([ 'openssl', 'pkeyutl', '-encap',
                  '-inkey', srctop_file('test', 'testrsa2048pub.pem'),
                  '-out', 'encap_out.bin', '-secret', 'secret.bin']))),
                  "RSA pubkey encapsulation");
    ok(run(app(([ 'openssl', 'pkeyutl', '-decap',
                  '-inkey', srctop_file('test', 'testrsa2048.pem'),
                  '-in', 'encap_out.bin', '-secret', 'decap_secret.bin']))),
                  "RSA pubkey decapsulation");
    is(compare("secret.bin", "decap_secret.bin"), 0, "Secret is correctly decapsulated");

    # Legacy CLI with decap output written to '-out' and with '-kemop` specified
    ok(run(app(([ 'openssl', 'pkeyutl', '-decap', '-kemop', 'RSASVE',
                  '-inkey', srctop_file('test', 'testrsa2048.pem'),
                  '-in', 'encap_out.bin', '-out', 'decap_out.bin']))),
                  "RSA pubkey decapsulation");
    is(compare("secret.bin", "decap_out.bin"), 0, "Secret is correctly decapsulated");

    # Pregenerated
    ok(run(app(([ 'openssl', 'pkeyutl', '-decap', '-kemop', 'RSASVE',
                  '-inkey', srctop_file('test', 'testrsa2048.pem'),
                  '-in', srctop_file('test', 'encap_out.bin'),
                  '-secret', 'decap_out_etl.bin']))),
                  "RSA pubkey decapsulation - pregenerated");

    is(compare(srctop_file('test', 'encap_secret.bin'), "decap_out_etl.bin"), 0,
               "Secret is correctly decapsulated - pregenerated");
}

subtest "pkeyutl -pkeyopt_passin" => sub {
    plan tests => 5;

    my @common = ('openssl', 'pkeyutl', '-kdf', 'TLS1-PRF', '-kdflen', '16',
                  '-pkeyopt', 'md:SHA256',
                  '-pkeyopt', 'seed:someseed');

    ok(run(app([@common, '-pkeyopt', 'secret:somesecret',
                '-out', 'tls1prf_plain.bin'])),
       "Derive with -pkeyopt secret");

    ok(run(app([@common, '-pkeyopt_passin', 'secret:pass:somesecret',
                '-out', 'tls1prf_passin.bin'])),
       "Derive with -pkeyopt_passin secret");

    is(compare('tls1prf_plain.bin', 'tls1prf_passin.bin'), 0,
       "pkeyopt_passin secret matches plain pkeyopt secret");

    # app_passwd failure: passphrase source cannot be read
    with({ exit_checker => sub { return shift == 1; } },
        sub {
            ok(run(app([@common, '-pkeyopt_passin',
                        'secret:file:no_such_passfile'])),
               "Fail when the passphrase source cannot be read");
        });

    # EVP_PKEY_CTX_ctrl_str failure: unknown control name
    with({ exit_checker => sub { return shift == 1; } },
        sub {
            ok(run(app([@common, '-pkeyopt_passin', 'bogus:pass:whatever'])),
               "Fail on unknown pkey option via passin");
        });
};

SKIP: {
    skip "EC is not supported by this OpenSSL build", 1
        if disabled("ec");

    subtest "pkeyutl -derive peer key setup" => sub {
        my $eckey = srctop_file("test", "testec-p256.pem");
        my $ecpub = srctop_file("test", "testecpub-p256.pem");
        my $rsapub = srctop_file("test", "testrsapub.pem");

        plan tests => 5;

        # ECDH derive against a matching peer public key
        ok(run(app(['openssl', 'pkeyutl', '-derive',
                    '-inkey', $eckey, '-peerkey', $ecpub,
                    '-out', 'derive_secret.bin'])),
           "Derive shared secret with matching peer key");

        # setup_peer: peer key file cannot be loaded
        with({ exit_checker => sub { return shift == 1; } },
            sub {
                ok(run(app(['openssl', 'pkeyutl', '-derive',
                            '-inkey', $eckey, '-peerkey', 'no_such_peer.pem'])),
                   "Fail when the peer key cannot be read");
            });

        # setup_peer: peer key type does not match the private key type
        with({ exit_checker => sub { return shift == 1; } },
            sub {
                ok(run(app(['openssl', 'pkeyutl', '-derive',
                            '-inkey', $eckey, '-peerkey', $rsapub])),
                   "Fail when peer key type does not match private key");
            });

        # main: -derive requires -peerkey
        with({ exit_checker => sub { return shift == 1; } },
            sub {
                ok(run(app(['openssl', 'pkeyutl', '-derive', '-inkey', $eckey])),
                   "Fail when -derive is given without -peerkey");
            });

        # main: -peerkey is only valid with -derive
        with({ exit_checker => sub { return shift == 1; } },
            sub {
                ok(run(app(['openssl', 'pkeyutl', '-inkey', $eckey, '-peerkey', $ecpub])),
                   "Fail when -peerkey is given without -derive");
            });
    };
}
