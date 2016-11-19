#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use File::Spec;
use MIME::Base64;
use OpenSSL::Test qw(:DEFAULT srctop_file bldtop_file);

my $test_name = "test_store";
setup($test_name);

my @noexist_files =
    ( "test/blahdiblah.pem",
      "test/blahdibleh.der" );
my @src_files =
    ( "test/testx509.pem",
      "test/testrsa.pem",
      "test/testrsapub.pem",
      "test/testcrl.pem",
      "apps/server.pem" );
my @generated_files =
    (
     ### generated from the source files

     "testx509.der",
     "testrsa.der",
     "testrsapub.der",
     "testcrl.der",

     ### generated locally
     ### These examples were pilfered from OpenConnect's test suite

     "rsa-key-pkcs1.pem", "rsa-key-pkcs1.der",
     "rsa-key-pkcs1-aes128.pem",
     "rsa-key-pkcs8.pem", "rsa-key-pkcs8.der",
     "rsa-key-pkcs8-pbes1-sha1-3des.pem", "rsa-key-pkcs8-pbes1-sha1-3des.der",
     "rsa-key-pkcs8-pbes2-sha1.pem", "rsa-key-pkcs8-pbes2-sha1.der",
     "rsa-key-sha1-3des-sha1.p12", "rsa-key-sha1-3des-sha256.p12",
     "rsa-key-aes256-cbc-sha256.p12",
     "rsa-key-md5-des-sha1.p12",
     "rsa-key-aes256-cbc-md5-des-sha256.p12",
     "rsa-key-pkcs8-pbes2-sha256.pem", "rsa-key-pkcs8-pbes2-sha256.der",
     "rsa-key-pkcs8-pbes1-md5-des.pem", "rsa-key-pkcs8-pbes1-md5-des.der",
     "dsa-key-pkcs1.pem", "dsa-key-pkcs1.der",
     "dsa-key-pkcs1-aes128.pem",
     "dsa-key-pkcs8.pem", "dsa-key-pkcs8.der",
     "dsa-key-pkcs8-pbes2-sha1.pem", "dsa-key-pkcs8-pbes2-sha1.der",
     "dsa-key-aes256-cbc-sha256.p12",
     "ec-key-pkcs1.pem", "ec-key-pkcs1.der",
     "ec-key-pkcs1-aes128.pem",
     "ec-key-pkcs8.pem", "ec-key-pkcs8.der",
     "ec-key-pkcs8-pbes2-sha1.pem", "ec-key-pkcs8-pbes2-sha1.der",
     "ec-key-aes256-cbc-sha256.p12",
    );

my $n = (2 * scalar @noexist_files)
    + (5 * scalar @src_files)
    + (3 * scalar @generated_files);

plan tests => $n;

indir "store_$$" => sub {
 SKIP:
    {
        skip "failed initialisation", $n unless init();

        foreach (@noexist_files) {
            my $file = srctop_file($_);
            ok(!run(app(["openssl", "storeutl", $file])));
            ok(!run(app(["openssl", "storeutl", to_file_uri($file)])));
        }
        foreach (@src_files) {
            my $file = srctop_file($_);
            ok(run(app(["openssl", "storeutl", $file])));
            ok(run(app(["openssl", "storeutl", to_file_uri($file)])));
            ok(run(app(["openssl", "storeutl", to_file_uri($file, 0,
                                                           "")])));
            ok(run(app(["openssl", "storeutl", to_file_uri($file, 0,
                                                           "localhost")])));
            ok(!run(app(["openssl", "storeutl", to_file_uri($file, 0,
                                                            "dummy")])));
        }
        foreach (@generated_files) {
        SKIP:
            {
                skip "PKCS#12 files not currently supported", 3 if m|\.p12$|;

                ok(run(app(["openssl", "storeutl", "-passin", "pass:password",
                            $_])));
                ok(run(app(["openssl", "storeutl", "-passin", "pass:password",
                            to_file_uri($_)])));
                ok(!run(app(["openssl", "storeutl", "-passin", "pass:password",
                             to_rel_file_uri($_)])));
            }
        }
    }
}, create => 1, cleanup => 1;

sub init {
    return (
            # rsa-key-pkcs1.pem
            run(app(["openssl", "genrsa",
                     "-out", "rsa-key-pkcs1.pem", "2432"]))
            # dsa-key-pkcs1.pem
            && run(app(["openssl", "dsaparam", "-genkey",
                        "-out", "dsa-key-pkcs1.pem", "1024"]))
            # ec-key-pkcs1.pem (one might think that 'genec' would be practical)
            && run(app(["openssl", "ecparam", "-genkey", "-name", "prime256v1",
                        "-out", "ec-key-pkcs1.pem"]))
            # rsa-key-pkcs1-aes128.pem
            && run(app(["openssl", "rsa", "-passout", "pass:password", "-aes128",
                        "-in", "rsa-key-pkcs1.pem",
                        "-out", "rsa-key-pkcs1-aes128.pem"]))
            # dsa-key-pkcs1-aes128.pem
            && run(app(["openssl", "dsa", "-passout", "pass:password", "-aes128",
                        "-in", "dsa-key-pkcs1.pem",
                        "-out", "dsa-key-pkcs1-aes128.pem"]))
            # ec-key-pkcs1-aes128.pem
            && run(app(["openssl", "ec", "-passout", "pass:password", "-aes128",
                        "-in", "ec-key-pkcs1.pem",
                        "-out", "ec-key-pkcs1-aes128.pem"]))
            # *-key-pkcs8.pem
            && runall(sub {
                          my $dstfile = shift;
                          (my $srcfile = $dstfile)
                              =~ s/-key-pkcs8\.pem$/-key-pkcs1.pem/i;
                          run(app(["openssl", "pkcs8", "-topk8", "-nocrypt",
                                   "-in", $srcfile, "-out", $dstfile]));
                      }, grep(/-key-pkcs8\.pem$/, @generated_files))
            # *-key-pkcs8-pbes1-sha1-3des.pem
            && runall(sub {
                          my $dstfile = shift;
                          (my $srcfile = $dstfile)
                              =~ s/-key-pkcs8-pbes1-sha1-3des\.pem$
                                  /-key-pkcs8.pem/ix;
                          run(app(["openssl", "pkcs8", "-topk8",
                                   "-passout", "pass:password",
                                   "-v1", "pbeWithSHA1And3-KeyTripleDES-CBC",
                                   "-in", $srcfile, "-out", $dstfile]));
                      }, grep(/-key-pkcs8-pbes1-sha1-3des\.pem$/, @generated_files))
            # *-key-pkcs8-pbes1-md5-des.pem
            && runall(sub {
                          my $dstfile = shift;
                          (my $srcfile = $dstfile)
                              =~ s/-key-pkcs8-pbes1-md5-des\.pem$
                                  /-key-pkcs8.pem/ix;
                          run(app(["openssl", "pkcs8", "-topk8",
                                   "-passout", "pass:password",
                                   "-v1", "pbeWithSHA1And3-KeyTripleDES-CBC",
                                   "-in", $srcfile, "-out", $dstfile]));
                      }, grep(/-key-pkcs8-pbes1-md5-des\.pem$/, @generated_files))
            # *-key-pkcs8-pbes2-sha1.pem
            && runall(sub {
                          my $dstfile = shift;
                          (my $srcfile = $dstfile)
                              =~ s/-key-pkcs8-pbes2-sha1\.pem$
                                  /-key-pkcs8.pem/ix;
                          run(app(["openssl", "pkcs8", "-topk8",
                                   "-passout", "pass:password",
                                   "-v2", "aes256", "-v2prf", "hmacWithSHA1",
                                   "-in", $srcfile, "-out", $dstfile]));
                      }, grep(/-key-pkcs8-pbes2-sha1\.pem$/, @generated_files))
            # *-key-pkcs8-pbes2-sha1.pem
            && runall(sub {
                          my $dstfile = shift;
                          (my $srcfile = $dstfile)
                              =~ s/-key-pkcs8-pbes2-sha256\.pem$
                                  /-key-pkcs8.pem/ix;
                          run(app(["openssl", "pkcs8", "-topk8",
                                   "-passout", "pass:password",
                                   "-v2", "aes256", "-v2prf", "hmacWithSHA256",
                                   "-in", $srcfile, "-out", $dstfile]));
                      }, grep(/-key-pkcs8-pbes2-sha256\.pem$/, @generated_files))
            # *.der (the end all init)
            && runall(sub {
                          my $dstfile = shift;
                          (my $srcfile = $dstfile) =~ s/\.der$/.pem/i;
                          if (! -f $srcfile) {
                              $srcfile = srctop_file("test", $srcfile);
                          }
                          my $infh;
                          unless (open $infh, $srcfile) {
                              return 0;
                          }
                          my $l;
                          while (($l = <$infh>) !~ /^-----BEGIN\s/
                                 || $l =~ /^-----BEGIN.*PARAMETERS-----/) {
                          }
                          my $b64 = "";
                          while (($l = <$infh>) !~ /^-----END\s/) {
                              $l =~ s|\R$||;
                              $b64 .= $l unless $l =~ /:/;
                          }
                          close $infh;
                          my $der = decode_base64($b64);
                          unless (length($b64) / 4 * 3 - length($der) < 3) {
                              print STDERR "Length error, ",length($b64),
                                  " bytes of base64 became ",length($der),
                                  " bytes of der? ($srcfile => $dstfile)\n";
                              return 0;
                          }
                          my $outfh;
                          unless (open $outfh, ">:raw", $dstfile) {
                              return 0;
                          }
                          print $outfh $der;
                          close $outfh;
                          return 1;
                      }, grep(/\.der$/, @generated_files))
           );
}

sub runall {
    my ($function, @items) = @_;

    foreach (@items) {
        return 0 unless $function->($_);
    }
    return 1;
}

# According to RFC8089, a relative file: path is invalid.  We still produce
# them for testing purposes.
sub to_rel_file_uri {
    my ($file, $isdir, $authority) = @_;
    my $vol;
    my $dir;

    die "to_rel_file_uri: No file given\n" if !defined($file) || $file eq '';

    ($vol, $dir, $file) = File::Spec->splitpath($file, $isdir // 0);

    # Make sure we have a Unix style directory.
    $dir = join('/', File::Spec->splitdir($dir));
    # Canonicalise it (note: it seems to be only needed on Unix)
    while (1) {
        my $newdir = $dir;
        $newdir =~ s|/[^/]*[^/\.]+[^/]*/\.\./|/|g;
        last if $newdir eq $dir;
        $dir = $newdir;
    }
    # Take care of the corner cases the loop can't handle, and that $dir
    # ends with a / unless it's empty
    $dir =~ s|/[^/]*[^/\.]+[^/]*/\.\.$|/|;
    $dir =~ s|^[^/]*[^/\.]+[^/]*/\.\./|/|;
    $dir =~ s|^[^/]*[^/\.]+[^/]*/\.\.$||;
    if ($isdir // 0) {
        $dir =~ s|/$|| if $dir ne '/';
    } else {
        $dir .= '/' if $dir ne '' && $dir !~ m|/$|;
    }

    # If the file system has separate volumes (at present, Windows and VMS)
    # we need to handle them.  In URIs, they are invariably the first
    # component of the path, which is always absolute.
    # On VMS, user:[foo.bar] translates to /user/foo/bar
    # On Windows, c:\Users\Foo translates to /c:/Users/Foo
    if ($vol ne '') {
        $vol =~ s|:||g if ($^O eq "VMS");
        $dir = '/' . $dir if $dir ne '' && $dir !~ m|^/|;
        $dir = '/' . $vol . $dir;
    }
    $file = $dir . $file;

    return "file://$authority$file" if defined $authority;
    return "file:$file";
}

sub to_file_uri {
    my ($file, $isdir, $authority) = @_;

    die "to_file_uri: No file given\n" if !defined($file) || $file eq '';
    return to_rel_file_uri(File::Spec->rel2abs($file), $isdir, $authority);
}
