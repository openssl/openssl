#! /usr/bin/env perl
# Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec::Functions;
use File::Copy;
use File::Basename;
use OpenSSL::Glob;
use OpenSSL::Test qw/:DEFAULT srctop_dir srctop_file/;

setup("test_rehash");

#If "openssl rehash -help" fails it's most likely because we're on a platform
#that doesn't support the rehash command (e.g. Windows)
plan skip_all => "test_rehash is not available on this platform"
    unless run(app(["openssl", "rehash", "-help"]));

plan tests => 6;

indir "rehash.$$" => sub {
    prepare();
    ok(run(app(["openssl", "rehash", curdir()])),
       'Testing normal rehash operations');
}, create => 1, cleanup => 1;

indir "rehash.$$" => sub {
    prepare(sub { chmod 400, $_ foreach (@_); });
    ok(run(app(["openssl", "rehash", curdir()])),
       'Testing rehash operations on readonly files');
}, create => 1, cleanup => 1;

indir "rehash.$$" => sub {
    ok(run(app(["openssl", "rehash", curdir()])),
       'Testing rehash operations on empty directory');
}, create => 1, cleanup => 1;

indir "rehash.$$" => sub {
    copy_fixtures(srctop_dir("test", "recipes", "40-test-rehash-good-data"));
    my $errfile = "rehash_err.txt";

    my @lines = run(app(["openssl", "rehash",
                        srctop_dir("test", "recipes", "40-test-rehash-bad-data")],
                        stderr => $errfile),
                        capture => 1, statusvar => \my $exit_ok);

    ok(!$exit_ok, 'rehash exited nonzero');

    #open(my $fh, '<', $errfile) or die "can't open $errfile: $!";
    #my @errlines = <$fh>;
    #close($fh);

    #ok(grep { /has an invalid PEM format/ } @errlines,
    #   'rehash warns about the invalid PEM');
}, create => 1, cleanup => 1;

indir "rehash.$$" => sub {
    copy_fixtures(srctop_dir("test", "recipes", "40-test-rehash-good-data"));
    my $errfile = "rehash_err.txt";

    run(app(["openssl", "rehash",
                        srctop_dir("test", "recipes", curdir())],
                        stderr => $errfile),
                        statusvar => \my $exit_ok);

    ok($exit_ok, 'rehash exits successfully with only valid PEM files');

    #open(my $fh, '<', $errfile) or die "can't open $errfile: $!";
    #my @errlines = <$fh>;
    #close($fh);

    #ok(!grep { /has an invalid PEM format/ } @errlines,
   #'rehash does not warn about invalid PEM when none are present');
}, create => 1, cleanup => 1;

indir "rehash.$$" => sub {
    prepare();
    chmod 0500, curdir();
  SKIP: {
      if (open(FOO, ">unwritable.txt")) {
          close FOO;
          skip "It's pointless to run the next test as root", 1;
      }
      isnt(run(app(["openssl", "rehash", curdir()])), 1,
           'Testing rehash operations on readonly directory');
    }
    chmod 0700, curdir();       # make it writable again, so cleanup works
}, create => 1, cleanup => 1;

sub prepare {
    my @pemsourcefiles = sort glob(srctop_file('test', "*.pem"));
    my @destfiles = ();

    die "There are no source files\n" if scalar @pemsourcefiles == 0;

    my $cnt = 0;
    foreach (@pemsourcefiles) {
        my $basename = basename($_, ".pem");
        my $writing = 0;

        open PEM, $_ or die "Can't read $_: $!\n";
        while (my $line = <PEM>) {
            if ($line =~ m{^-----BEGIN (?:CERTIFICATE|X509 CRL)-----}) {
                die "New start in a PEM blob?\n" if $writing;
                $cnt++;
                my $destfile =
                    catfile(curdir(),
                            $basename . sprintf("-%02d", $cnt) . ".pem");
                push @destfiles, $destfile;
                open OUT, '>', $destfile
                    or die "Can't write $destfile\n";
                $writing = 1;
            }
            print OUT $line if $writing;
            if ($line =~ m|^-----END |) {
                close OUT if $writing;
                $writing = 0;
            }
        }
        die "No end marker in $basename\n" if $writing;
    }
    die "No test PEM files produced\n" if $cnt == 0;

    foreach (@_) {
        die "Internal error, argument is not CODE"
            unless (ref($_) eq 'CODE');
        $_->(@destfiles);
    }
}

sub copy_fixtures {
    my ($srcdir) = @_;
    my @srcfiles = sort glob(catfile($srcdir, "*"));
    my @destfiles = ();

    foreach my $f (@srcfiles) {
        next unless -f $f;
        my $dest = catfile(curdir(), basename($f));
        copy($f, $dest) or die "Can't copy $f to $dest: $!\n";
        push @destfiles, $dest;
    }
    return @destfiles;
}
