#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Copy qw/copy/;
use IO::Socket::INET;
use OpenSSL::Test qw/:DEFAULT srctop_file bldtop_file/;
use OpenSSL::Test::Utils;

setup("test_tsget");

plan skip_all => "TS is not supported by this OpenSSL build"
    if disabled("ts");

plan skip_all => "fork() is not available on this platform"
    if $^O =~ /^(MSWin32|VMS)$/;

plan skip_all => "tsget is not available (not built)"
    unless -f bldtop_file("apps", "tsget.pl");

eval { require Net::Curl::Easy };
plan skip_all => "Net::Curl::Easy is not available"
    if $@;

plan tests => 12;

indir "tsget" => sub {
    my $openssl_conf = srctop_file("test", "CAtsa.cnf");
    my $tsacakey     = srctop_file("test", "certs", "ca-key.pem");
    my $alt1_key     = srctop_file("test", "certs", "alt1-key.pem");
    my ($normal_pid, $normal_port);

    # These two tests exercise tsget argument validation before any network
    # or TSA infrastructure is needed.

    subtest "missing -h flag" => sub {
        plan tests => 1;
        ok(!run(perlapp(["tsget.pl", "test.tsq"])),
           "tsget exits non-zero without -h");
    };

    subtest "multiple files combined with -o" => sub {
        plan tests => 1;
        ok(!run(perlapp(["tsget.pl", "-h", "http://127.0.0.1:1",
                         "-o", "combined.tsr", "test.tsq", "test2.tsq"])),
           "tsget exits non-zero with -o and multiple input files");
    };

 SKIP: {
    skip "TSA infrastructure setup failed", 10
        unless setup_tsa_infrastructure($openssl_conf, $tsacakey, $alt1_key);

    ($normal_pid, $normal_port) = start_mock_tsa_server(
        mode          => 'normal',
        response_file => 'canned.tsr',
    );

  SKIP: {
    skip "could not start normal mock server", 8 unless defined $normal_pid;

    my $url = "http://127.0.0.1:$normal_port";

    subtest "default output extension (.tsr)" => sub {
        plan tests => 3;
        ok(run(perlapp(["tsget.pl", "-v", "-h", $url, "test.tsq"])),
           "tsget runs successfully");
        ok(-f "test.tsr", "output file test.tsr created");
        ok(run(app(["openssl", "ts", "-verify",
                    "-queryfile", "test.tsq",
                    "-in", "test.tsr",
                    "-CAfile", "tsaca.pem",
                    "-untrusted", "tsa_cert.pem"])),
           "timestamp reply is cryptographically valid");
    };

    subtest "custom extension (-e .reply)" => sub {
        plan tests => 3;
        ok(run(perlapp(["tsget.pl", "-v", "-e", ".reply", "-h", $url, "test.tsq"])),
           "tsget runs with -e .reply");
        ok(-f "test.reply", "output file test.reply created");
        ok(run(app(["openssl", "ts", "-verify",
                    "-queryfile", "test.tsq",
                    "-in", "test.reply",
                    "-CAfile", "tsaca.pem",
                    "-untrusted", "tsa_cert.pem"])),
           "timestamp reply is cryptographically valid");
    };

    subtest "custom output file (-o)" => sub {
        plan tests => 3;
        ok(run(perlapp(["tsget.pl", "-v", "-o", "custom.tsr", "-h", $url, "test.tsq"])),
           "tsget runs with -o");
        ok(-f "custom.tsr", "custom output file created");
        ok(run(app(["openssl", "ts", "-verify",
                    "-queryfile", "test.tsq",
                    "-in", "custom.tsr",
                    "-CAfile", "tsaca.pem",
                    "-untrusted", "tsa_cert.pem"])),
           "timestamp reply is cryptographically valid");
    };

    subtest "stdin input" => sub {
        plan tests => 3;
        ok(run(perlapp(["tsget.pl", "-v", "-o", "stdin.tsr", "-h", $url],
                       stdin => "test.tsq")),
           "tsget runs with stdin input");
        ok(-f "stdin.tsr", "output file stdin.tsr created");
        ok(run(app(["openssl", "ts", "-verify",
                    "-queryfile", "test.tsq",
                    "-in", "stdin.tsr",
                    "-CAfile", "tsaca.pem",
                    "-untrusted", "tsa_cert.pem"])),
           "timestamp reply is cryptographically valid");
    };

    subtest "debug mode (-d)" => sub {
        plan tests => 1;
        ok(run(perlapp(["tsget.pl", "-d", "-o", "debug.tsr", "-h", $url, "test.tsq"])),
           "tsget runs with -d flag");
    };

    subtest "TSGET environment variable" => sub {
        plan tests => 3;
        local $ENV{TSGET} = "-v -e .envtsr -h $url";
        ok(run(perlapp(["tsget.pl", "test.tsq"])),
           "tsget uses TSGET environment variable");
        ok(-f "test.envtsr", "output file test.envtsr created");
        ok(run(app(["openssl", "ts", "-verify",
                    "-queryfile", "test.tsq",
                    "-in", "test.envtsr",
                    "-CAfile", "tsaca.pem",
                    "-untrusted", "tsa_cert.pem"])),
           "timestamp reply is cryptographically valid");
    };

    subtest "multiple input files" => sub {
        plan tests => 4;
      SKIP: {
        skip "could not copy test.tsq to test2.tsq", 4
            unless copy("test.tsq", "test2.tsq");
        ok(run(perlapp(["tsget.pl", "-v", "-h", $url, "test.tsq", "test2.tsq"])),
           "tsget processes two input files");
        ok(-f "test.tsr",  "output test.tsr created for first file");
        ok(-f "test2.tsr", "output test2.tsr created for second file");
        ok(run(app(["openssl", "ts", "-verify",
                    "-queryfile", "test.tsq",
                    "-in", "test.tsr",
                    "-CAfile", "tsaca.pem",
                    "-untrusted", "tsa_cert.pem"])),
           "first timestamp reply is cryptographically valid");
        }
    };

    subtest "input file in subdirectory" => sub {
        plan tests => 3;
      SKIP: {
        mkdir "subdir" unless -d "subdir";
        skip "could not set up subdir/test.tsq", 3
            unless -d "subdir" && copy("test.tsq", "subdir/test.tsq");
        ok(run(perlapp(["tsget.pl", "-v", "-h", $url, "subdir/test.tsq"])),
           "tsget derives output path from input path");
        ok(-f "subdir/test.tsr",
           "output placed in same directory as input");
        ok(run(app(["openssl", "ts", "-verify",
                    "-queryfile", "subdir/test.tsq",
                    "-in", "subdir/test.tsr",
                    "-CAfile", "tsaca.pem",
                    "-untrusted", "tsa_cert.pem"])),
           "timestamp reply is cryptographically valid");
        }
    };
    }

    subtest "HTTP server error response" => sub {
        plan tests => 2;
        my ($pid, $port) = start_mock_tsa_server(
            mode         => 'error',
            http_code    => 500,
            max_requests => 1,
        );
      SKIP: {
        skip "could not start error server", 2 unless defined $pid;
        ok(!run(perlapp(["tsget.pl", "-h", "http://127.0.0.1:$port",
                         "-o", "err_http.tsr", "test.tsq"])),
           "tsget exits non-zero on HTTP 500");
        ok(!-f "err_http.tsr",
           "partial output file removed after HTTP error");
        }
        waitpid($pid, 0) if defined $pid;
    };

    subtest "empty server response" => sub {
        plan tests => 2;
        my ($pid, $port) = start_mock_tsa_server(
            mode         => 'empty',
            max_requests => 1,
        );
      SKIP: {
        skip "could not start empty server", 2 unless defined $pid;
        ok(!run(perlapp(["tsget.pl", "-h", "http://127.0.0.1:$port",
                         "-o", "err_empty.tsr", "test.tsq"])),
           "tsget exits non-zero on empty response");
        ok(!-f "err_empty.tsr",
           "partial output file removed after empty response");
        }
        waitpid($pid, 0) if defined $pid;
    };
    }

    if (defined $normal_pid) {
        kill 'TERM', $normal_pid;
        waitpid($normal_pid, 0);
    }

}, create => 1, cleanup => 1;


# Set up a local TSA: CA cert, signing cert/key, TSA config, and a
# pre-generated timestamp response that the mock server will return for
# every request.
sub setup_tsa_infrastructure {
    my ($conf, $cakey, $signerkey) = @_;

    local $ENV{TSDNSECT} = "ts_ca_dn";

    run(app(["openssl", "req",
             "-config", $conf, "-new", "-x509", "-noenc",
             "-out", "tsaca.pem", "-key", $cakey]))
        or do { diag "Failed to create TSA CA cert"; return 0; };

    local $ENV{TSDNSECT} = "ts_cert_dn";
    local $ENV{INDEX}    = "1";

    run(app(["openssl", "req",
             "-config", $conf, "-new",
             "-out", "tsa_req.pem",
             "-key", $signerkey,
             "-keyout", "tsa_key.pem"]))
        or do { diag "Failed to create TSA cert request"; return 0; };

    run(app(["openssl", "x509", "-req",
             "-in", "tsa_req.pem",
             "-out", "tsa_cert.pem",
             "-CA", "tsaca.pem", "-CAkey", $cakey,
             "-CAcreateserial",
             "-extfile", $conf, "-extensions", "tsa_cert"]))
        or do { diag "Failed to sign TSA cert"; return 0; };

    open(my $cfh, ">", "local_tsa.cnf")
        or do { diag "Failed to write local_tsa.cnf: $!"; return 0; };
    print $cfh <<'END_CNF';
[ tsa ]
default_tsa = tsa_config1

[ tsa_config1 ]
dir               = .
serial            = $dir/tsa_serial
signer_cert       = $dir/tsa_cert.pem
certs             = $dir/tsaca.pem
signer_key        = $dir/tsa_key.pem
signer_digest     = sha256
default_policy    = 1.2.3.4.1
digests           = sha1, sha256, sha384, sha512
ordering          = yes
tsa_name          = yes
ess_cert_id_chain = yes
ess_cert_id_alg   = sha256
END_CNF
    close $cfh;

    open(my $sfh, ">", "tsa_serial")
        or do { diag "Failed to write tsa_serial: $!"; return 0; };
    print $sfh "01\n";
    close $sfh;

    run(app(["openssl", "ts", "-query",
             "-data", $conf, "-sha256", "-cert",
             "-out", "test.tsq"]))
        or do { diag "Failed to create timestamp query"; return 0; };

    run(app(["openssl", "ts", "-reply",
             "-config", "local_tsa.cnf",
             "-queryfile", "test.tsq",
             "-chain", "tsaca.pem",
             "-out", "canned.tsr"]))
        or do { diag "Failed to generate canned timestamp response"; return 0; };

    return 1;
}


# Fork a minimal HTTP server.  Behaviour is controlled by %opts:
#   mode          => 'normal' (default): serve $response_file for every POST
#                 => 'error':  return HTTP $http_code with an empty body
#                 => 'empty':  return HTTP 200 with Content-Length: 0
#   response_file => path to the canned response (used by 'normal' mode)
#   http_code     => HTTP status for 'error' mode (default 500)
#   max_requests  => stop after this many requests; 0 means unlimited (default)
sub start_mock_tsa_server {
    my %opts = @_;
    my $mode          = $opts{mode}          // 'normal';
    my $response_file = $opts{response_file};
    my $http_code     = $opts{http_code}     // 500;
    my $max_requests  = $opts{max_requests}  // 0;

    my $sock = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1',
        LocalPort => 0,
        Type      => SOCK_STREAM,
        Listen    => 5,
        ReuseAddr => 1,
    ) or do { diag "Failed to create server socket: $!"; return (undef, undef); };

    my $port = $sock->sockport();

    my $pid = fork();
    if (!defined $pid) {
        $sock->close();
        diag "fork() failed: $!";
        return (undef, undef);
    }

    if ($pid == 0) {
        my $n = 0;
        while (my $client = $sock->accept()) {
            my $content_length = 0;
            while (my $line = <$client>) {
                $line =~ s/\r?\n$//;
                last if $line eq '';
                $content_length = $1
                    if $line =~ /^Content-Length:\s*(\d+)/i;
            }
            my $body = '';
            read($client, $body, $content_length) if $content_length > 0;

            if ($mode eq 'normal' && defined $response_file
                && open(my $fh, '<', $response_file)) {
                binmode $fh;
                local $/;
                my $reply = <$fh>;
                close $fh;
                my $len = length($reply);
                print $client
                    "HTTP/1.0 200 OK\r\n",
                    "Content-Type: application/timestamp-reply\r\n",
                    "Content-Length: $len\r\n",
                    "\r\n",
                    $reply;
            } elsif ($mode eq 'empty') {
                print $client
                    "HTTP/1.0 200 OK\r\n",
                    "Content-Type: application/timestamp-reply\r\n",
                    "Content-Length: 0\r\n",
                    "\r\n";
            } else {
                print $client "HTTP/1.0 $http_code Server Error\r\n\r\n";
            }
            $client->close();
            ++$n;
            last if $max_requests > 0 && $n >= $max_requests;
        }
        exit 0;
    }

    $sock->close();
    select(undef, undef, undef, 0.1);

    return ($pid, $port);
}
