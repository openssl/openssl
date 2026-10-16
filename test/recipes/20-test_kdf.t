#! /usr/bin/env perl
# Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use OpenSSL::Test;
use OpenSSL::Test::Utils;

setup("test_kdf");

my @kdf_tests = (
    { cmd => [qw{openssl kdf -keylen 16 -digest SHA256 -kdfopt secret:secret -kdfopt seed:seed TLS1-PRF}],
      expected => '8E:4D:93:25:30:D7:65:A0:AA:E9:74:C3:04:73:5E:CC',
      desc => 'TLS1-PRF SHA256' },
    { cmd => [qw{openssl kdf -keylen 16 -digest MD5-SHA1 -kdfopt secret:secret -kdfopt seed:seed TLS1-PRF}],
      expected => '65:6F:31:CB:04:03:D6:51:E2:E8:71:F8:20:04:AB:BA',
      desc => 'TLS1-PRF MD5-SHA1' },
    { cmd => [qw{openssl kdf -keylen 10 -digest SHA256 -kdfopt key:secret -kdfopt salt:salt -kdfopt info:label HKDF}],
      expected => '2a:c4:36:9f:52:59:96:f8:de:13',
      desc => 'HKDF SHA256' },
    { cmd => [qw{openssl kdf -keylen 10 -kdfopt key:secret -kdfopt salt:salt -kdfopt info:label HKDF-SHA256}],
      expected => '2a:c4:36:9f:52:59:96:f8:de:13',
      desc => 'HKDF-SHA256' },
    { cmd => [qw{openssl kdf -keylen 25 -digest SHA256 -kdfopt pass:passwordPASSWORDpassword -kdfopt salt:saltSALTsaltSALTsaltSALTsaltSALTsalt -kdfopt iter:4096 PBKDF2}],
      expected => '34:8C:89:DB:CB:D3:2B:2F:32:D8:14:B8:11:6E:84:CF:2B:17:34:7E:BC:18:00:18:1C',
      desc => 'PBKDF2 SHA256'},

    # Using the -kdfopt digest: option instead of -digest
    { cmd => [qw{openssl kdf -keylen 16 -kdfopt digest:SHA256 -kdfopt secret:secret -kdfopt seed:seed TLS1-PRF}],
      expected => '8E:4D:93:25:30:D7:65:A0:AA:E9:74:C3:04:73:5E:CC',
      desc => 'TLS1-PRF SHA256' },
    { cmd => [qw{openssl kdf -keylen 16 -kdfopt digest:MD5-SHA1 -kdfopt secret:secret -kdfopt seed:seed TLS1-PRF}],
      expected => '65:6F:31:CB:04:03:D6:51:E2:E8:71:F8:20:04:AB:BA',
      desc => 'TLS1-PRF MD5-SHA1' },
    { cmd => [qw{openssl kdf -keylen 10 -kdfopt digest:SHA256 -kdfopt key:secret -kdfopt salt:salt -kdfopt info:label HKDF}],
      expected => '2a:c4:36:9f:52:59:96:f8:de:13',
      desc => 'HKDF SHA256' },
    { cmd => [qw{openssl kdf -keylen 25 -kdfopt digest:SHA256 -kdfopt pass:passwordPASSWORDpassword -kdfopt salt:saltSALTsaltSALTsaltSALTsaltSALTsalt -kdfopt iter:4096 PBKDF2}],
      expected => '34:8C:89:DB:CB:D3:2B:2F:32:D8:14:B8:11:6E:84:CF:2B:17:34:7E:BC:18:00:18:1C',
      desc => 'PBKDF2 SHA256'},
);

my @sshkdf_tests = (
    { cmd => [qw{openssl kdf -keylen 16 -digest SHA256 -kdfopt hexkey:0102030405 -kdfopt hexxcghash:06090A -kdfopt hexsession_id:01020304 -kdfopt type:A SSHKDF}],
      expected => '5C:49:94:47:3B:B1:53:3A:58:EB:19:42:04:D3:78:16',
      desc => 'SSHKDF SHA256'},
    { cmd => [qw{openssl kdf -keylen 16 -kdfopt digest:SHA256 -kdfopt hexkey:0102030405 -kdfopt hexxcghash:06090A -kdfopt hexsession_id:01020304 -kdfopt type:A SSHKDF}],
      expected => '5C:49:94:47:3B:B1:53:3A:58:EB:19:42:04:D3:78:16',
      desc => 'SSHKDF SHA256'},
);

my @sskdf_tests = (
   { cmd => [qw{openssl kdf -keylen 64 -mac KMAC128 -kdfopt maclen:20 -kdfopt hexkey:b74a149a161546f8c20b06ac4ed4 -kdfopt hexinfo:348a37a27ef1282f5f020dcc -kdfopt hexsalt:3638271ccd68a25dc24ecddd39ef3f89 SSKDF}],
      expected => 'e9:c1:84:53:a0:62:b5:3b:db:fc:bb:5a:34:bd:b8:e5:e7:07:ee:bb:5d:d1:34:42:43:d8:cf:c2:c2:e6:33:2f:91:bd:a5:86:f3:7d:e4:8a:65:d4:c5:14:fd:ef:aa:1e:67:54:f3:73:d2:38:e1:95:ae:15:7e:1d:e8:14:98:03',
      desc => 'SSKDF KMAC128'},
    { cmd => [qw{openssl kdf -keylen 16 -mac HMAC -kdfopt digest:SHA256 -kdfopt hexkey:b74a149a161546f8c20b06ac4ed4 -kdfopt hexinfo:348a37a27ef1282f5f020dcc -kdfopt hexsalt:3638271ccd68a25dc24ecddd39ef3f89 SSKDF}],
      expected => '44:f6:76:e8:5c:1b:1a:8b:bc:3d:31:92:18:63:1c:a3',
      desc => 'SSKDF HMAC SHA256'},
    { cmd => [qw{openssl kdf -keylen 14 -kdfopt digest:SHA224 -kdfopt hexkey:6dbdc23f045488e4062757b06b9ebae183fc5a5946d80db93fec6f62ec07e3727f0126aed12ce4b262f47d48d54287f81d474c7c3b1850e9 -kdfopt hexinfo:a1b2c3d4e54341565369643c832e9849dcdba71e9a3139e606e095de3c264a66e98a165854cd07989b1ee0ec3f8dbe SSKDF}],
      expected => 'a4:62:de:16:a8:9d:e8:46:6e:f5:46:0b:47:b8',
      desc => 'SSKDF HASH SHA224'},
    # Additionally using -kdfopt mac: instead of -mac
    { cmd => [qw{openssl kdf -keylen 64 -kdfopt mac:KMAC128 -kdfopt maclen:20 -kdfopt hexkey:b74a149a161546f8c20b06ac4ed4 -kdfopt hexinfo:348a37a27ef1282f5f020dcc -kdfopt hexsalt:3638271ccd68a25dc24ecddd39ef3f89 SSKDF}],
      expected => 'e9:c1:84:53:a0:62:b5:3b:db:fc:bb:5a:34:bd:b8:e5:e7:07:ee:bb:5d:d1:34:42:43:d8:cf:c2:c2:e6:33:2f:91:bd:a5:86:f3:7d:e4:8a:65:d4:c5:14:fd:ef:aa:1e:67:54:f3:73:d2:38:e1:95:ae:15:7e:1d:e8:14:98:03',
      desc => 'SSKDF KMAC128'},
    { cmd => [qw{openssl kdf -keylen 16 -kdfopt mac:HMAC -kdfopt digest:SHA256 -kdfopt hexkey:b74a149a161546f8c20b06ac4ed4 -kdfopt hexinfo:348a37a27ef1282f5f020dcc -kdfopt hexsalt:3638271ccd68a25dc24ecddd39ef3f89 SSKDF}],
      expected => '44:f6:76:e8:5c:1b:1a:8b:bc:3d:31:92:18:63:1c:a3',
      desc => 'SSKDF HMAC SHA256'},
);

my @krb5kdf_tests = (
    { cmd => [qw{openssl kdf -keylen 16 -cipher AES-128-CBC -kdfopt hexkey:42263C6E89F4FC28B8DF68EE09799F15 -kdfopt hexconstant:0000000299 KRB5KDF}],
      expected => '34:28:0A:38:2B:C9:27:69:B2:DA:2F:9E:F0:66:85:4B',
      desc => 'KRB5KDF AES-128-CBC'},
    { cmd => [qw{openssl kdf -keylen 32 -cipher AES-256-CBC -kdfopt hexkey:FE697B52BC0D3CE14432BA036A92E65BBB52280990A2FA27883998D72AF30161 -kdfopt hexconstant:0000000299 KRB5KDF}],
      expected => 'BF:AB:38:8B:DC:B2:38:E9:F9:C9:8D:6A:87:83:04:F0:4D:30:C8:25:56:37:5A:C5:07:A7:A8:52:79:0F:46:74',
      desc => 'KRB5KDF AES-256-CBC'},
    # Using the -kdfopt cipher: option instead of -cipher
    { cmd => [qw{openssl kdf -keylen 16 -kdfopt cipher:AES-128-CBC -kdfopt hexkey:42263C6E89F4FC28B8DF68EE09799F15 -kdfopt hexconstant:0000000299 KRB5KDF}],
      expected => '34:28:0A:38:2B:C9:27:69:B2:DA:2F:9E:F0:66:85:4B',
      desc => 'KRB5KDF AES-128-CBC'},
);

my @multi_common = (qw{openssl kdf -multi -digest SHA256
    -kdfopt secret:secret -kdfopt seed:seed
    -kdfopt mac_key_len:10 -kdfopt cipher_key_len:16 -kdfopt iv_len:6});

my @kdf_multi_tests = (
    { cmd => [@multi_common, '-purpose', 'client_MAC_key', 'TLS1-PRF'],
      expected => '8E:4D:93:25:30:D7:65:A0:AA:E9',
      desc => 'TLS1-PRF multi-derive client_MAC_key' },
    { cmd => [@multi_common, '-purpose', 'server_MAC_key', 'TLS1-PRF'],
      expected => '74:C3:04:73:5E:CC:12:02:A8:19',
      desc => 'TLS1-PRF multi-derive server_MAC_key' },
    { cmd => [@multi_common, '-purpose', 'client_cipher_key', 'TLS1-PRF'],
      expected => 'F8:0A:DB:D5:AD:09:C1:A3:4F:C0:69:18:E3:D0:77:95',
      desc => 'TLS1-PRF multi-derive client_cipher_key' },
    { cmd => [@multi_common, '-purpose', 'server_cipher_key', 'TLS1-PRF'],
      expected => '21:4D:94:C6:A1:97:6C:AE:A5:A0:B6:44:C5:B0:4D:1A',
      desc => 'TLS1-PRF multi-derive server_cipher_key' },
    { cmd => [@multi_common, '-purpose', 'client_iv', 'TLS1-PRF'],
      expected => 'D3:E0:9C:61:11:C3',
      desc => 'TLS1-PRF multi-derive client_iv' },
    { cmd => [@multi_common, '-purpose', 'server_iv', 'TLS1-PRF'],
      expected => '7A:FC:00:DF:0B:6D',
      desc => 'TLS1-PRF multi-derive server_iv' },
);

# Naming the cipher the keys are for tells the provider how long the cipher
# key is, so cipher_key_len need not be given.  A MAC does not determine its
# own key length, so mac_key_len is still required.
my @alg_common = (qw{openssl kdf -multi -digest SHA256
    -kdfopt secret:secret -kdfopt seed:seed
    -kdfopt mac_key_len:10 -kdfopt iv_len:6});

my @kdf_multi_alg_tests = (
    # Same value as the cipher_key_len:16 test above, reached via the cipher name
    { cmd => [@alg_common, qw{-cipher AES-128-CBC -purpose client_cipher_key TLS1-PRF}],
      expected => 'F8:0A:DB:D5:AD:09:C1:A3:4F:C0:69:18:E3:D0:77:95',
      desc => 'TLS1-PRF multi-derive takes the key length from AES-128-CBC' },
    { cmd => [@alg_common, qw{-cipher AES-256-CBC -purpose client_cipher_key TLS1-PRF}],
      expected => 'F8:0A:DB:D5:AD:09:C1:A3:4F:C0:69:18:E3:D0:77:95:'
                  . '21:4D:94:C6:A1:97:6C:AE:A5:A0:B6:44:C5:B0:4D:1A',
      desc => 'TLS1-PRF multi-derive takes the key length from AES-256-CBC' },
    { cmd => [@alg_common, qw{-cipher AES-128-CBC -mac HMAC
                              -purpose client_MAC_key TLS1-PRF}],
      expected => '8E:4D:93:25:30:D7:65:A0:AA:E9',
      desc => 'TLS1-PRF multi-derive MAC key length still comes from mac_key_len' },
    # A longer cipher key moves the IVs further down the key block
    { cmd => [@alg_common, qw{-cipher AES-256-CBC -purpose server_iv TLS1-PRF}],
      expected => '6E:5D:B1:41:53:72',
      desc => 'TLS1-PRF multi-derive IV placement follows the cipher key length' },
);

my @kdf_multi_fail_tests = (
    { cmd => [@alg_common, qw{-cipher AES-128-CBC -kdfopt cipher_key_len:10
                              -purpose client_cipher_key TLS1-PRF}],
      desc => 'TLS1-PRF multi-derive rejects a length the named cipher cannot take' },
    { cmd => [@alg_common, qw{-cipher AES-128-CBC -purpose nonexistent TLS1-PRF}],
      desc => 'TLS1-PRF multi-derive rejects an unknown purpose' },
);

my @tls13_multi_common = (qw{openssl kdf -multi -kdfopt mode:EXPAND_ONLY -kdfopt digest:SHA256},
    '-kdfopt', 'hexkey:c80583a90e995c489600492a5da642e6b1f679ba674828792df087b939636171',
    '-kdfopt', 'hexdata:7c92f68bd5bf3638ea338a6494722e1b44127e1b7e8aad535f2322a644ff22b3',
    '-kdfopt', 'hexprefix:746c73313320',
    qw{-kdfopt cipher_key_len:16 -kdfopt iv_len:12});

my @kdf_tls13_multi_tests = (
    { cmd => [@tls13_multi_common, '-purpose', 'client_key', 'TLS13-KDF'],
      expected => '37:06:C9:0F:B4:7B:1E:1E:F5:E0:19:BC:BD:22:67:34',
      desc => 'TLS13-KDF multi-derive client_key' },
    { cmd => [@tls13_multi_common, '-purpose', 'server_key', 'TLS13-KDF'],
      expected => '37:06:C9:0F:B4:7B:1E:1E:F5:E0:19:BC:BD:22:67:34',
      desc => 'TLS13-KDF multi-derive server_key' },
    { cmd => [@tls13_multi_common, '-purpose', 'client_iv', 'TLS13-KDF'],
      expected => '82:65:EC:2B:D2:B2:7C:F3:1E:B3:DD:F7',
      desc => 'TLS13-KDF multi-derive client_iv' },
    { cmd => [@tls13_multi_common, '-purpose', 'server_iv', 'TLS13-KDF'],
      expected => '82:65:EC:2B:D2:B2:7C:F3:1E:B3:DD:F7',
      desc => 'TLS13-KDF multi-derive server_iv' },
);

my @kdf_bin_tests = (
    { cmd => [qw{openssl kdf -keylen 10 -binary -out hkdf-sha256.bin -kdfopt digest:SHA256 -kdfopt key:secret -kdfopt salt:salt -kdfopt info:label HKDF}],
      outfile => 'hkdf-sha256.bin',
      expected => '2ac4369f525996f8de13',
      desc => 'HKDF SHA256 binary output' },
);

my @scrypt_tests = (
    { cmd => [qw{openssl kdf -keylen 64 -kdfopt pass:password -kdfopt salt:NaCl -kdfopt n:1024 -kdfopt r:8 -kdfopt p:16 -kdfopt maxmem_bytes:10485760 id-scrypt}],
      expected => 'fd:ba:be:1c:9d:34:72:00:78:56:e7:19:0d:01:e9:fe:7c:6a:d7:cb:c8:23:78:30:e7:73:76:63:4b:37:31:62:2e:af:30:d9:2e:22:a3:88:6f:f1:09:27:9d:98:30:da:c7:27:af:b9:4a:83:ee:6d:83:60:cb:df:a2:cc:06:40',
      desc => 'SCRYPT' },
);

push @kdf_tests, @krb5kdf_tests unless disabled("krb5kdf");
push @kdf_tests, @scrypt_tests unless disabled("scrypt");
push @kdf_tests, @sshkdf_tests unless disabled("sshkdf");
push @kdf_tests, @sskdf_tests unless disabled("sskdf");

plan tests => scalar @kdf_tests + scalar @kdf_multi_tests
    + scalar @kdf_multi_alg_tests + scalar @kdf_multi_fail_tests
    + scalar @kdf_tls13_multi_tests + scalar @kdf_bin_tests;

foreach (@kdf_tests) {
    ok(compareline($_->{cmd}, $_->{expected}), $_->{desc});
}

foreach (@kdf_multi_tests) {
    ok(compareline($_->{cmd}, $_->{expected}), $_->{desc});
}

foreach (@kdf_multi_alg_tests) {
    ok(compareline($_->{cmd}, $_->{expected}), $_->{desc});
}

foreach (@kdf_multi_fail_tests) {
    ok(checkfail($_->{cmd}), $_->{desc});
}

foreach (@kdf_tls13_multi_tests) {
    ok(compareline($_->{cmd}, $_->{expected}), $_->{desc});
}

foreach (@kdf_bin_tests) {
    ok(comparebinary($_->{cmd}, $_->{outfile}, $_->{expected}), $_->{desc});
}

# Check that the stdout output matches the expected value.
sub compareline {
    my ($cmdarray, $expect) = @_;
    if (defined($expect)) {
        $expect = uc $expect;
    }

    my @lines = run(app($cmdarray), capture => 1);

    if (defined($expect)) {
        if ($lines[0] =~ m|^\Q${expect}\E\R$|) {
            return 1;
        } else {
            diag("Got: $lines[0]");
            diag("Exp: $expect");
            return 0;
        }
    }
    return 0;
}

# Check that the command fails rather than producing output.
sub checkfail {
    my ($cmdarray) = @_;
    my $status = 1;

    run(app($cmdarray), capture => 1, statusvar => \$status);
    return !$status;
}

# Check that the binary output file matches the expected value.
sub comparebinary {
    my ($cmdarray, $outfile, $expect) = @_;

    return 0 unless run(app($cmdarray));

    open(my $fh, '<:raw', $outfile) or return 0;
    my $got = unpack('H*', do { local $/; <$fh> });
    close($fh);

    if ($got ne lc $expect) {
        diag("Got: $got");
        diag("Exp: $expect");
        return 0;
    }
    return 1;
}
