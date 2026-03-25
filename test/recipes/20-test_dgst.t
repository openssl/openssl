#! /usr/bin/env perl
# Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use File::Basename;
use OpenSSL::Test qw/:DEFAULT with srctop_file srctop_dir data_file bldtop_dir/;
use OpenSSL::Test::Utils;
use Cwd qw(abs_path);

setup("test_dgst");

plan tests => 25;

sub tsignverify {
    my $testtext = shift;
    my $privkey = shift;
    my $pubkey = shift;

    my $data_to_sign = srctop_file('test', 'data.bin');
    my $other_data = srctop_file('test', 'data2.bin');

    my $sigfile = basename($privkey, '.pem') . '.sig';
    plan tests => 4;

    ok(run(app(['openssl', 'dgst', '-sign', $privkey,
                '-out', $sigfile,
                $data_to_sign])),
       $testtext.": Generating signature");

    ok(run(app(['openssl', 'dgst', '-prverify', $privkey,
                '-signature', $sigfile,
                $data_to_sign])),
       $testtext.": Verify signature with private key");

    ok(run(app(['openssl', 'dgst', '-verify', $pubkey,
                '-signature', $sigfile,
                $data_to_sign])),
       $testtext.": Verify signature with public key");

    ok(!run(app(['openssl', 'dgst', '-verify', $pubkey,
                 '-signature', $sigfile,
                 $other_data])),
       $testtext.": Expect failure verifying mismatching data");
}

sub tsignverify_sha512 {
    my $testtext = shift;
    my $privkey = shift;
    my $pubkey = shift;

    my $data_to_sign = srctop_file('test', 'data.bin');
    my $other_data = srctop_file('test', 'data2.bin');

    my $sigfile = basename($privkey, '.pem') . '.sig';
    plan tests => 5;

    ok(run(app(['openssl', 'sha512', '-sign', $privkey,
                '-out', $sigfile,
                $data_to_sign])),
       $testtext.": Generating signature using sha512 command");

    ok(run(app(['openssl', 'sha512', '-verify', $pubkey,
                '-signature', $sigfile,
                $data_to_sign])),
       $testtext.": Verify signature with public key using sha512 command");

    ok(run(app(['openssl', 'dgst', '-sha512', '-prverify', $privkey,
                '-signature', $sigfile,
                $data_to_sign])),
       $testtext.": Verify signature with private key");

    ok(run(app(['openssl', 'dgst', '-sha512', '-verify', $pubkey,
                '-signature', $sigfile,
                $data_to_sign])),
       $testtext.": Verify signature with public key");

    ok(!run(app(['openssl', 'dgst', '-sha512', '-verify', $pubkey,
                 '-signature', $sigfile,
                 $other_data])),
       $testtext.": Expect failure verifying mismatching data");
}

subtest "RSA signature generation and verification with `dgst` CLI" => sub {
    if (disabled("rsa")) {
        plan tests => 1;
        ok(1, "Skipped (RSA not supported)");
        return;
    }
    tsignverify("RSA",
                srctop_file("test","testrsa.pem"),
                srctop_file("test","testrsapub.pem"));
};

subtest "RSA signature generation and verification with `sha512` CLI" => sub {
    if (disabled("rsa")) {
        plan tests => 1;
        ok(1, "Skipped (RSA not supported)");
        return;
    }
    tsignverify_sha512("RSA",
                       srctop_file("test","testrsa2048.pem"),
                       srctop_file("test","testrsa2048pub.pem"));
};

subtest "DSA signature generation and verification with `dgst` CLI" => sub {
    if (disabled("dsa")) {
        plan tests => 1;
        ok(1, "Skipped (DSA not supported)");
        return;
    }
    tsignverify("DSA",
                srctop_file("test","testdsa.pem"),
                srctop_file("test","testdsapub.pem"));
};

subtest "ECDSA signature generation and verification with `dgst` CLI" => sub {
    if (disabled("ec")) {
        plan tests => 1;
        ok(1, "Skipped (ECDSA not supported)");
        return;
    }
    tsignverify("ECDSA",
                srctop_file("test","testec-p256.pem"),
                srctop_file("test","testecpub-p256.pem"));
};

subtest "Ed25519 signature generation and verification with `dgst` CLI" => sub {
    if (disabled("ecx")) {
        plan tests => 1;
        ok(1, "Skipped (EdDSA not supported)");
        return;
    }
    tsignverify("Ed25519",
                srctop_file("test","tested25519.pem"),
                srctop_file("test","tested25519pub.pem"));
};

subtest "Ed448 signature generation and verification with `dgst` CLI" => sub {
    if (disabled("ecx")) {
        plan tests => 1;
        ok(1, "Skipped (EdDSA not supported)");
        return;
    }
    tsignverify("Ed448",
                srctop_file("test","tested448.pem"),
                srctop_file("test","tested448pub.pem"));
};

subtest "dgst one-shot: no buffer fallback when mmap path fails (Unix)" => sub {
    if ($^O eq 'MSWin32' || disabled("ecx")) {
        plan tests => 1;
        ok(1, "Skipped (Unix/mmap or EdDSA not available)");
        return;
    }
    plan tests => 2;

    # Use a directory with non-zero st_size so app_mmap_file() attempts open+mmap
    # (curdir "." often has st_size 0 on some FS, which skips mmap and breaks this test).
    # mmap() on a directory must fail; we must not fall back to bio_to_mem.
    my $key = srctop_file("test", "tested25519.pem");
    my $dir = srctop_dir("test");
    my $stderr_file = "dgst_nofallback_err.txt";

    with({ exit_checker => sub { return shift != 0; } },
         sub {
             ok(run(app(['openssl', 'dgst', '-sign', $key, $dir],
                        stderr => $stderr_file)),
                "dgst one-shot with un-mmapable file fails (no fallback)");
         });
    if (open(my $fh, '<', $stderr_file)) {
        my $err = do { local $/; <$fh> };
        close($fh);
        ok($err =~ /Error: failed to use memory-mapped file/, "stderr mentions mmap failure");
    } else {
        ok(0, "could not read stderr file");
    }
    unlink($stderr_file) if -f $stderr_file;
};

subtest "ML-DSA-44 signature generation and verification with `dgst` CLI" => sub {
    if (disabled("ml-dsa")) {
        plan tests => 1;
        ok(1, "Skipped (ML-DSA not supported)");
        return;
    }
    tsignverify("Ml-DSA-44",
                srctop_file("test","testmldsa44.pem"),
                srctop_file("test","testmldsa44pub.pem"));
};
subtest "ML-DSA-65 signature generation and verification with `dgst` CLI" => sub {
    if (disabled("ml-dsa")) {
        plan tests => 1;
        ok(1, "Skipped (ML-DSA not supported)");
        return;
    }
    tsignverify("Ml-DSA-65",
                srctop_file("test","testmldsa65.pem"),
                srctop_file("test","testmldsa65pub.pem"));
};
subtest "ML-DSA-87 signature generation and verification with `dgst` CLI" => sub {
    if (disabled("ml-dsa")) {
        plan tests => 1;
        ok(1, "Skipped (ML-DSA not supported)");
        return;
    }
    tsignverify("Ml-DSA-87",
                srctop_file("test","testmldsa87.pem"),
                srctop_file("test","testmldsa87pub.pem"));
};

subtest "SHA1 generation by provider with `dgst` CLI" => sub {
    if (disabled("module")) {
        plan tests => 1;
        ok(1, "Skipped (dgst with provider not supported)");
        return;
    }
    plan tests => 1;

    $ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("test"));
        my $testdata = srctop_file('test', 'data.bin');
        my @macdata = run(app(['openssl', 'dgst', '-sha1',
                               '-provider', "p_ossltest",
                               '-provider', "default",
                               '-propquery', '?provider=p_ossltest',
                               $testdata]), capture => 1);
        chomp(@macdata);
        my $expected = qr/SHA1\(\Q$testdata\E\)= 000102030405060708090a0b0c0d0e0f10111213/;
        ok($macdata[0] =~ $expected, "SHA1: Check HASH value is as expected ($macdata[0]) vs ($expected)");
};

subtest "HMAC generation with `dgst` CLI" => sub {
    plan tests => 2;

    my $testdata = srctop_file('test', 'data.bin');
    #HMAC the data twice to check consistency
    my @hmacdata = run(app(['openssl', 'dgst', '-sha256', '-hmac', '123456',
                            $testdata, $testdata]), capture => 1);
    chomp(@hmacdata);
    my $expected = qr/HMAC-SHA2-256\(\Q$testdata\E\)= 6f12484129c4a761747f13d8234a1ff0e074adb34e9e9bf3a155c391b97b9a7c/;
    ok($hmacdata[0] =~ $expected, "HMAC: Check HMAC value is as expected ($hmacdata[0]) vs ($expected)");
    ok($hmacdata[1] =~ $expected,
       "HMAC: Check second HMAC value is consistent with the first ($hmacdata[1]) vs ($expected)");
};

subtest "HMAC generation with `dgst` CLI, default digest" => sub {
    plan tests => 2;

    my $testdata = srctop_file('test', 'data.bin');
    #HMAC the data twice to check consistency
    my @hmacdata = run(app(['openssl', 'dgst', '-hmac', '123456',
                            $testdata, $testdata]), capture => 1);
    chomp(@hmacdata);
    my $expected = qr/HMAC-SHA256\(\Q$testdata\E\)= 6f12484129c4a761747f13d8234a1ff0e074adb34e9e9bf3a155c391b97b9a7c/;
    ok($hmacdata[0] =~ $expected, "HMAC: Check HMAC value is as expected ($hmacdata[0]) vs ($expected)");
    ok($hmacdata[1] =~ $expected,
       "HMAC: Check second HMAC value is consistent with the first ($hmacdata[1]) vs ($expected)");
};

subtest "HMAC generation with `dgst` CLI, key via environment" => sub {
    plan tests => 2;

    my $testdata = srctop_file('test', 'data.bin');
    #HMAC the data twice to check consistency
    local $ENV{MYKEY} = 123456;
    my @hmacdata = run(app(['openssl', 'dgst', '-sha256', '-hmac-env', 'MYKEY',
                            $testdata, $testdata]), capture => 1);
    chomp(@hmacdata);
    my $expected = qr/HMAC-SHA2-256\(\Q$testdata\E\)= 6f12484129c4a761747f13d8234a1ff0e074adb34e9e9bf3a155c391b97b9a7c/;
    ok($hmacdata[0] =~ $expected, "HMAC: Check HMAC value is as expected ($hmacdata[0]) vs ($expected)");
    ok($hmacdata[1] =~ $expected,
       "HMAC: Check second HMAC value is consistent with the first ($hmacdata[1]) vs ($expected)");
};

subtest "HMAC generation with `dgst` CLI, key via stdin" => sub {
    plan tests => 2;

    my $testdata = srctop_file('test', 'data.bin');
    #HMAC the data twice to check consistency
    my @hmacdata = run(app(['openssl', 'dgst', '-sha256', '-hmac-stdin',
                            $testdata, $testdata], stdin => data_file("keyfile.txt")), capture => 1);
    chomp(@hmacdata);
    my $expected = qr/HMAC-SHA2-256\(\Q$testdata\E\)= 6f12484129c4a761747f13d8234a1ff0e074adb34e9e9bf3a155c391b97b9a7c/;
    ok($hmacdata[0] =~ $expected, "HMAC: Check HMAC value is as expected ($hmacdata[0]) vs ($expected)");
    ok($hmacdata[1] =~ $expected,
       "HMAC: Check second HMAC value is consistent with the first ($hmacdata[1]) vs ($expected)");
};

subtest "HMAC generation with `dgst` CLI, key via option key" => sub {
    plan tests => 2;

    my $testdata = srctop_file('test', 'data.bin');
    #HMAC the data twice to check consistency
    my @hmacdata = run(app(['openssl', 'dgst', '-sha256', '-mac', 'HMAC',
                            '-macopt', 'key:123456',
                            $testdata, $testdata]), capture => 1);
    chomp(@hmacdata);
    my $expected = qr/HMAC-SHA2-256\(\Q$testdata\E\)= 6f12484129c4a761747f13d8234a1ff0e074adb34e9e9bf3a155c391b97b9a7c/;
    ok($hmacdata[0] =~ $expected, "HMAC: Check HMAC value is as expected ($hmacdata[0]) vs ($expected)");
    ok($hmacdata[1] =~ $expected,
       "HMAC: Check second HMAC value is consistent with the first ($hmacdata[1]) vs ($expected)");
};

subtest "HMAC generation with `dgst` CLI, key via option hexkey" => sub {
    plan tests => 2;

    my $testdata = srctop_file('test', 'data.bin');
    #HMAC the data twice to check consistency
    my @hmacdata = run(app(['openssl', 'dgst', '-sha256', '-mac', 'HMAC',
                            '-macopt', 'hexkey:FFFF',
                            $testdata, $testdata]), capture => 1);
    chomp(@hmacdata);
    my $expected = qr/HMAC-SHA2-256\(\Q$testdata\E\)= 7c02d4a17d2560a5bb6763edbf33f3a34f415398f8f2e07f04b83ffd7c087dae/;
    ok($hmacdata[0] =~ $expected, "HMAC: Check HMAC value is as expected ($hmacdata[0]) vs ($expected)");
    ok($hmacdata[1] =~ $expected,
       "HMAC: Check second HMAC value is consistent with the first ($hmacdata[1]) vs ($expected)");
};

subtest "HMAC generation with `dgst` CLI, key via option keyenv" => sub {
    plan tests => 2;

    my $testdata = srctop_file('test', 'data.bin');
    #HMAC the data twice to check consistency
    local $ENV{MYKEY} = '123456';
    my @hmacdata = run(app(['openssl', 'dgst', '-sha256', '-mac', 'HMAC',
                            '-macopt', 'keyenv:MYKEY',
                            $testdata, $testdata]), capture => 1);
    chomp(@hmacdata);
    my $expected = qr/HMAC-SHA2-256\(\Q$testdata\E\)= 6f12484129c4a761747f13d8234a1ff0e074adb34e9e9bf3a155c391b97b9a7c/;
    ok($hmacdata[0] =~ $expected, "HMAC: Check HMAC value is as expected ($hmacdata[0]) vs ($expected)");
    ok($hmacdata[1] =~ $expected,
       "HMAC: Check second HMAC value is consistent with the first ($hmacdata[1]) vs ($expected)");
};

subtest "HMAC generation with `dgst` CLI, key via option keyenvhex" => sub {
    plan tests => 2;

    my $testdata = srctop_file('test', 'data.bin');
    #HMAC the data twice to check consistency
    local $ENV{MYKEY} = 'FFFF';
    my @hmacdata = run(app(['openssl', 'dgst', '-sha256', '-mac', 'HMAC',
                            '-macopt', 'keyenvhex:MYKEY',
                            $testdata, $testdata]), capture => 1);
    chomp(@hmacdata);
    my $expected = qr/HMAC-SHA2-256\(\Q$testdata\E\)= 7c02d4a17d2560a5bb6763edbf33f3a34f415398f8f2e07f04b83ffd7c087dae/;
    ok($hmacdata[0] =~ $expected, "HMAC: Check HMAC value is as expected ($hmacdata[0]) vs ($expected)");
    ok($hmacdata[1] =~ $expected,
       "HMAC: Check second HMAC value is consistent with the first ($hmacdata[1]) vs ($expected)");
};

subtest "HMAC generation with `dgst` CLI, key via option keyfile" => sub {
    plan tests => 2;

    my $testdata = srctop_file('test', 'data.bin');
    #HMAC the data twice to check consistency
    my @hmacdata = run(app(['openssl', 'dgst', '-sha256', '-mac', 'HMAC',
                            '-macopt', 'keyfile:' . data_file("keyfile.bin"),
                            $testdata, $testdata]), capture => 1);
    chomp(@hmacdata);
    my $expected = qr/HMAC-SHA2-256\(\Q$testdata\E\)= 7c02d4a17d2560a5bb6763edbf33f3a34f415398f8f2e07f04b83ffd7c087dae/;
    ok($hmacdata[0] =~ $expected, "HMAC: Check HMAC value is as expected ($hmacdata[0]) vs ($expected)");
    ok($hmacdata[1] =~ $expected,
       "HMAC: Check second HMAC value is consistent with the first ($hmacdata[1]) vs ($expected)");
};

subtest "HMAC generation with `dgst` CLI, key via option keystdin" => sub {
    plan tests => 2;

    my $testdata = srctop_file('test', 'data.bin');
    #HMAC the data twice to check consistency
    my @hmacdata = run(app(['openssl', 'dgst', '-sha256', '-mac', 'HMAC',
                            '-macopt', 'keystdin',
                            $testdata, $testdata], stdin => data_file("keyfile.txt")), capture => 1);
    chomp(@hmacdata);
    my $expected = qr/HMAC-SHA2-256\(\Q$testdata\E\)= 6f12484129c4a761747f13d8234a1ff0e074adb34e9e9bf3a155c391b97b9a7c/;
    ok($hmacdata[0] =~ $expected, "HMAC: Check HMAC value is as expected ($hmacdata[0]) vs ($expected)");
    ok($hmacdata[1] =~ $expected,
       "HMAC: Check second HMAC value is consistent with the first ($hmacdata[1]) vs ($expected)");
};

subtest "Custom length XOF digest generation with `dgst` CLI" => sub {
    plan tests => 2;

    my $testdata = srctop_file('test', 'data.bin');
    #Digest the data twice to check consistency
    my @xofdata = run(app(['openssl', 'dgst', '-shake128', '-xoflen', '64',
                           $testdata, $testdata]), capture => 1);
    chomp(@xofdata);
    my $expected = qr/SHAKE-128\(\Q$testdata\E\)= bb565dac72640109e1c926ef441d3fa64ffd0b3e2bf8cd73d5182dfba19b6a8a2eab96d2df854b647b3795ef090582abe41ba4e0717dc4df40bc4e17d88e4677/;
    ok($xofdata[0] =~ $expected, "XOF: Check digest value is as expected ($xofdata[0]) vs ($expected)");
    ok($xofdata[1] =~ $expected,
       "XOF: Check second digest value is consistent with the first ($xofdata[1]) vs ($expected)");
};

subtest "SHAKE digest generation with no xoflen set `dgst` CLI" => sub {
    plan tests => 2;

    my $testdata = srctop_file('test', 'data.bin');
    ok(!run(app(['openssl', 'dgst', '-shake128', $testdata])), "SHAKE128 must fail without xoflen");
    ok(!run(app(['openssl', 'dgst', '-shake256', $testdata])), "SHAKE256 must fail without xoflen");
};

subtest "signing with xoflen is not supported `dgst` CLI" => sub {
    if (disabled("ec")) {
        plan tests => 1;
        ok(1, "Skipped (ECDSA not supported)");
        return;
    }
    plan tests => 1;
    my $data_to_sign = srctop_file('test', 'data.bin');

    ok(!run(app(['openssl', 'dgst', '-shake256', '-xoflen', '64',
                 '-sign', srctop_file("test","testec-p256.pem"),
                 '-out', 'test.sig',
                 srctop_file('test', 'data.bin')])),
                 "Generating signature with xoflen should fail");
};

subtest "signing using the nonce-type sigopt" => sub {
    if (disabled("ec")) {
        plan tests => 1;
        ok(1, "Skipped (ECDSA not supported)");
        return;
    }
    if (disabled("hmac-drbg-kdf")) {
        plan tests => 1;
        ok(1, "Skipped (HMAC-DRBG-KDF not supported)");
        return;
    }
    plan tests => 1;
    my $data_to_sign = srctop_file('test', 'data.bin');

    ok(run(app(['openssl', 'dgst', '-sha256',
                 '-sign', srctop_file("test","testec-p256.pem"),
                 '-out', 'test.sig',
                 '-sigopt', 'nonce-type:1',
                 srctop_file('test', 'data.bin')])),
                 "Sign using the nonce-type sigopt");
};
