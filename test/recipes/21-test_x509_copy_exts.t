#! /usr/bin/env perl
# Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_x509_copy_exts");

plan tests => 12;

my $req = srctop_file('test','x509-copy-exts-req.pem');
my $cert = srctop_file('test','certs','x509-copy-exts-cert.pem');
my $key = srctop_file('test','certs','x509-copy-exts-key.pem');
my $cnf = srctop_file('test', 'x509-copy-exts.cnf');

my $temp_cert1 = "temp_cert1.pem";
my $temp_cert1_txt = "temp_cert1.txt";
my $temp_cert2 = "temp_cert2.pem";
my $temp_cert2_txt = "temp_cert2.txt";
my $temp_req1 = "temp_req1.pem";
my $temp_req1_txt = "temp_req1.txt";
my $temp_req2 = "temp_req2.pem";
my $temp_req2_txt = "temp_req2.txt";

my $flag = 0;

ok(run(app(["openssl", "x509", "-req", "-in", $req,
            "-out", $temp_cert1, "-signkey", $key,
            "-copy_extensions", "none"])));
ok(run(app(["openssl", "x509", "-text", "-in", $temp_cert1,
            "-out", $temp_cert1_txt, "-noout"])));
$flag = check_in_file($temp_cert1_txt, 'X509v3 extensions:');
unlink $temp_cert1;
unlink $temp_cert1_txt;
ok($flag == 0, 'Check absence of extensions in cert #1');
$flag = 0;

ok(run(app(["openssl", "x509", "-text", "-req", "-in", $req,
            "-out", $temp_cert2, "-signkey", $key,
            "-copy_extensions", "copyall"])));
ok(run(app(["openssl", "x509", "-text", "-in", $temp_cert2,
            "-out", $temp_cert2_txt, "-noout"])));
$flag = check_in_file($temp_cert2_txt, 'X509v3 extensions:');
unlink $temp_cert2;
unlink $temp_cert2_txt;
ok($flag == 1, 'Check presence of extensions in cert #2');
$flag = 0;

ok(run(app(["openssl", "x509", "-x509toreq", "-in", $cert,
            "-out", $temp_req1, "-signkey", $key,
            "-copy_extensions", "none"])));
ok(run(app(["openssl", "req", "-text", "-in", $temp_req1,
            "-out", $temp_req1_txt, "-noout", "-config", $cnf])));
$flag = check_in_file($temp_req1_txt, 'Requested Extensions:');
unlink $temp_req1;
unlink $temp_req1_txt;
ok($flag == 0, 'Check absence of extensions in req #1');
$flag = 0;

ok(run(app(["openssl", "x509", "-x509toreq", "-in", $cert,
            "-out", $temp_req2, "-signkey", $key,
            "-copy_extensions", "copyall"])));
ok(run(app(["openssl", "req", "-text", "-in", $temp_req2,
            "-out", $temp_req2_txt, "-noout", "-config", $cnf])));
$flag = check_in_file($temp_req2_txt, 'Requested Extensions:');
unlink $temp_req2;
unlink $temp_req2_txt;
ok($flag == 1, 'Check presence of extensions in req #2');
$flag = 0;

sub check_in_file
{
    my ($path, $str) = @_;
    my $flag_ = 0;
    if ( open(FFF, $path) )
    {
        while (<FFF>)
        {
            print $_;
            if ( index($_, $str) != -1)
            {
                $flag_ = 1;
                last;
            }
        }
        close (FFF);
    }
    else
    {
        $flag_ = 2;
    }
    return $flag_;
}
