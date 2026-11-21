#!/usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Generate test certificates for EAI (Email Address Internationalization)
# name constraint verification tests.
#
# Usage: perl gen_nc_eai_certs.pl [output_directory]

use strict;
use warnings;
use File::Spec;

my $outdir = $ARGV[0] // ".";

die "Output directory '$outdir' does not exist\n" unless -d $outdir;

my $openssl = $ENV{OPENSSL} // "openssl";

# Helper to run openssl commands
sub runcmd {
    my @cmd = @_;
    system(@cmd) == 0 or die "Command failed: @cmd\n";
}

# Leading-dot base: CA permits .example.com, leaf has user@sub.example.com
my $dotbase_key  = File::Spec->catfile($outdir, "nc-eai-dotbase-key.pem");
my $dotbase_root = File::Spec->catfile($outdir, "nc-eai-dotbase-root.pem");
my $dotbase_leaf_key = File::Spec->catfile($outdir, "nc-eai-dotbase-leaf-key.pem");
my $dotbase_leaf_csr = File::Spec->catfile($outdir, "nc-eai-dotbase-leaf.csr");
my $dotbase_leaf = File::Spec->catfile($outdir, "nc-eai-dotbase-leaf.pem");

runcmd($openssl, "req", "-x509", "-new", "-newkey", "rsa:2048", "-nodes",
       "-keyout", $dotbase_key, "-subj", "/CN=NC EAI Dot Base CA",
       "-days", "36500",
       "-addext", "basicConstraints=critical,CA:TRUE",
       "-addext", "nameConstraints=critical,permitted;email:.example.com",
       "-out", $dotbase_root);
runcmd($openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes",
       "-keyout", $dotbase_leaf_key, "-subj", "/CN=NC EAI Dot Base Leaf",
       "-addext", 'subjectAltName=otherName:1.3.6.1.5.5.7.8.9;UTF8:user@sub.example.com',
       "-out", $dotbase_leaf_csr);
runcmd($openssl, "x509", "-req", "-in", $dotbase_leaf_csr,
       "-CA", $dotbase_root, "-CAkey", $dotbase_key, "-CAcreateserial",
       "-days", "36500", "-copy_extensions", "copyall",
       "-out", $dotbase_leaf);

# Full email base: CA permits testuser@example.com
my $atbase_key  = File::Spec->catfile($outdir, "nc-eai-atbase-key.pem");
my $atbase_root = File::Spec->catfile($outdir, "nc-eai-atbase-root.pem");
my $atbase_leaf_key = File::Spec->catfile($outdir, "nc-eai-atbase-leaf-key.pem");
my $atbase_leaf_csr = File::Spec->catfile($outdir, "nc-eai-atbase-leaf.csr");
my $atbase_leaf = File::Spec->catfile($outdir, "nc-eai-atbase-leaf.pem");

runcmd($openssl, "req", "-x509", "-new", "-newkey", "rsa:2048", "-nodes",
       "-keyout", $atbase_key, "-subj", "/CN=NC EAI At Base CA",
       "-days", "36500",
       "-addext", "basicConstraints=critical,CA:TRUE",
       "-addext", 'nameConstraints=critical,permitted;email:testuser@example.com',
       "-out", $atbase_root);
runcmd($openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes",
       "-keyout", $atbase_leaf_key, "-subj", "/CN=NC EAI At Base Leaf",
       "-addext", 'subjectAltName=otherName:1.3.6.1.5.5.7.8.9;UTF8:testuser@example.com',
       "-out", $atbase_leaf_csr);
runcmd($openssl, "x509", "-req", "-in", $atbase_leaf_csr,
       "-CA", $atbase_root, "-CAkey", $atbase_key, "-CAcreateserial",
       "-days", "36500", "-copy_extensions", "copyall",
       "-out", $atbase_leaf);

# Negative test leaf: wronguser@example.com signed by atbase CA
my $wrong_leaf_key = File::Spec->catfile($outdir, "nc-eai-atbase-wrong-key.pem");
my $wrong_leaf_csr = File::Spec->catfile($outdir, "nc-eai-atbase-wrong.csr");
my $wrong_leaf     = File::Spec->catfile($outdir, "nc-eai-atbase-wrong-leaf.pem");

runcmd($openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes",
       "-keyout", $wrong_leaf_key, "-subj", "/CN=NC EAI At Base Wrong Leaf",
       "-addext", 'subjectAltName=otherName:1.3.6.1.5.5.7.8.9;UTF8:wronguser@example.com',
       "-out", $wrong_leaf_csr);
runcmd($openssl, "x509", "-req", "-in", $wrong_leaf_csr,
       "-CA", $atbase_root, "-CAkey", $atbase_key, "-CAcreateserial",
       "-days", "36500", "-copy_extensions", "copyall",
       "-out", $wrong_leaf);

# Clean up intermediate files (keys, CSRs, serials)
for my $f ($dotbase_key, $dotbase_leaf_key, $dotbase_leaf_csr,
           $atbase_key, $atbase_leaf_key, $atbase_leaf_csr,
           $wrong_leaf_key, $wrong_leaf_csr) {
    unlink $f if -f $f;
}
# Clean up serial files (.srl)
for my $srl (glob(File::Spec->catfile($outdir, "*.srl"))) {
    unlink $srl;
}

print "Generated EAI name constraint test certificates in $outdir\n";
