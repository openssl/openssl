#! /usr/bin/env perl
# Copyright 2015-2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec::Functions qw/catfile/;
use File::Copy;
use File::Compare qw/compare_text/;
use File::Basename;
use OpenSSL::Test qw/:DEFAULT srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;

setup("test_enc");
plan skip_all => "Deprecated functions are disabled in this OpenSSL build"
    if disabled("deprecated");

# We do it this way, because setup() may have moved us around,
# so the directory portion of $0 might not be correct any more.
# However, the name hasn't changed.
my $testsrc = srctop_file("test","recipes",basename($0));

my $test = catfile(".", "p");

my $cmd = "openssl";
my $provpath = bldtop_dir("providers");
my @prov = ("-provider-path", $provpath, "-provider", "default");
push @prov, ("-provider", "legacy") unless disabled("legacy");
my $ciphersstatus = undef;
my @ciphers =
    map { s/^\s+//; s/\s+$//; split /\s+/ }
    run(app([$cmd, "list", "-cipher-commands"]),
        capture => 1, statusvar => \$ciphersstatus);
@ciphers = grep {!/^(bf|cast|des$|des-cbc|des-cfb|des-ecb|des-ofb|desx|idea
                     |rc2|rc4|seed)/x} @ciphers
    if disabled("legacy");

plan tests => 6 + (scalar @ciphers)*2;

 SKIP: {
     skip "Problems getting ciphers...", 1 + scalar(@ciphers)
         unless ok($ciphersstatus, "Running 'openssl list -cipher-commands'");
     unless (ok(copy($testsrc, $test), "Copying $testsrc to $test")) {
         diag($!);
         skip "Not initialized, skipping...", scalar(@ciphers);
     }

     foreach my $c (@ciphers) {
         my %variant = ("$c" => [],
                        "$c base64" => [ "-a" ]);

         foreach my $t (sort keys %variant) {
             my $cipherfile = "$test.$c.cipher";
             my $clearfile = "$test.$c.clear";
             my @e = ( "$c", "-bufsize", "113", @{$variant{$t}}, "-e", "-k", "test" );
             my @d = ( "$c", "-bufsize", "157", @{$variant{$t}}, "-d", "-k", "test" );
             if ($c eq "cat") {
                 $cipherfile = "$test.cipher";
                 $clearfile = "$test.clear";
                 @e = ( "enc", @{$variant{$t}}, "-e" );
                 @d = ( "enc", @{$variant{$t}}, "-d" );
             }

             ok(run(app([$cmd, @e, @prov, "-in", $test, "-out", $cipherfile]))
                && run(app([$cmd, @d, @prov, "-in", $cipherfile, "-out", $clearfile]))
                && compare_text($test,$clearfile) == 0, $t);
         }
     }
     ok(run(app([$cmd, "enc", "-in", $test, "-aes256", "-pbkdf2", "-out",
                 "salted_default.cipher", "-pass", "pass:password"]))
        && run(app([$cmd, "enc", "-d", "-in", "salted_default.cipher", "-aes256", "-pbkdf2",
                    "-saltlen", "8", "-out", "salted_default.clear", "-pass", "pass:password"]))
        && compare_text($test,"salted_default.clear") == 0,
        "Check that the default salt length of 8 bytes is used for PKDF2");

     ok(!run(app([$cmd, "enc", "-d", "-in", "salted_default.cipher", "-aes256", "-pbkdf2",
                  "-saltlen", "16", "-out", "salted_fail.clear", "-pass", "pass:password"])),
        "Check the decrypt fails if the saltlen is incorrect");

     ok(run(app([$cmd, "enc", "-in", $test, "-aes256", "-pbkdf2", "-saltlen", "16",
                 "-out", "salted.cipher", "-pass", "pass:password"]))
        && run(app([$cmd, "enc", "-d", "-in", "salted.cipher", "-aes256", "-pbkdf2",
                    "-saltlen", "16", "-out", "salted.clear", "-pass", "pass:password"]))
        && compare_text($test,"salted.clear") == 0,
        "Check that we can still use a salt length of 16 bytes for PKDF2");

#./util/wrap.pl apps/openssl enc -aes128 -K 30313032303330343035303630373038 -iv 100f0e0d0c0b0a090807060504030201 -in 1.txt -out 2.enc
#./util/wrap.pl apps/openssl enc -aes128 -skeyuri skeyfile.bin -iv 100f0e0d0c0b0a090807060504030201 -in 1.txt -out 1.enc
     my $folder = "test/recipes/20-test_enc_data";
     my $skeyuri = srctop_file($folder, "skeyfile.bin");
     ok(run(app([$cmd, "enc", "-in", $test, "-aes128", "-K", "30313032303330343035303630373038",
                 "-iv", "100f0e0d0c0b0a090807060504030201",
                 "-out", "key_from_cmdline.enc"]))
        && run(app([$cmd, "enc", "-in", $test, "-aes128", "-skeyuri", $skeyuri,
                 "-iv", "100f0e0d0c0b0a090807060504030201",
                 "-out", "key_from_uri.enc" ]))
        && File::Compare::compare("key_from_cmdline.enc", "key_from_uri.enc") == 0,
        "Check that key from URI gives an equal result comparing to the explicit one");
}
