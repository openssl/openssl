#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License"). You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# WIP local-only regression for https://github.com/openssl/openssl/issues/32223
# Must show a baseline-to-fix result before being considered validated.
# TLSProxy uses an isolated OpenSSL test provider and loopback sockets only.

use strict;
use warnings;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;
use Cwd qw(abs_path);
use Digest::SHA qw(sha256_hex);
use MIME::Base64 qw(decode_base64);
use File::Temp qw(tempdir);
use POSIX ();

setup("test_tls13sigcertfallback");

$ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("test"));

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;
plan skip_all => "Requires modules, sockets and TLS 1.3"
    if disabled("module") || disabled("sock") || disabled("tls1_3");
plan skip_all => "Requires EC or DH key exchange"
    if disabled("ec") && disabled("dh");

# Extract the DER bytes from an existing, known test certificate.
# Comparing a SHA-256 fingerprint of the actual TLS Certificate message
# avoids mistaking a client-side verification failure for server rejection.
sub pem_cert_sha256 {
    my ($filename) = @_;
    open my $fh, '<', $filename or die "Cannot read $filename: $!";
    local $/;
    my $pem = <$fh>;
    close $fh;

    my ($body) = $pem =~ /-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----/s;
    die "Invalid PEM certificate in $filename" unless defined $body;
    $body =~ s/\s+//g;
    return sha256_hex(decode_base64($body));
}

my $key = srctop_file("test", "certs", "ee-key.pem");
my $ca = srctop_file("test", "certs", "ca-cert.pem");
my $sha256_cert = srctop_file("test", "certs", "ee-cert.pem");
my $sha1_cert = srctop_file("test", "certs", "ee-rsa-sha1-cert.pem");
my $sha1_intermediate = srctop_file("test", "certs",
    "ca-rsa-sha1-intermediate-32223.pem");
my $sha1_intermediate_chain = srctop_file("test", "certs",
    "ca-sha1-intermediate-chain-32223.pem");
my $sha1_anchor = srctop_file("test", "certs",
    "ca-selfsigned-sha1-anchor-32223.pem");
my $sha256_via_intermediate = srctop_file("test", "certs",
    "ee-sha256-via-sha1-intermediate-32223.pem");
my $root = srctop_file("test", "certs", "root-cert.pem");
my $client_root = srctop_file("test", "certs", "rootcert.pem");
my $auto_store = srctop_file("test", "certs", "ca-root-chain-32223.pem");
my $ecdsa_cert = srctop_file("test", "certs", "server-ecdsa-cert.pem");
my $ecdsa_key = srctop_file("test", "certs", "server-ecdsa-key.pem");
my $ecdsa_fingerprint = pem_cert_sha256($ecdsa_cert);
my $client_pss_cert = srctop_file("test", "certs", "client-pss-restrict-cert.pem");
my $client_pss_key = srctop_file("test", "certs", "client-pss-restrict-key.pem");
my $client_pss_fingerprint = pem_cert_sha256($client_pss_cert);
my $sha256_fingerprint = pem_cert_sha256($sha256_cert);
my $sha1_fingerprint = pem_cert_sha256($sha1_cert);
my $sha1_intermediate_fingerprint = pem_cert_sha256($sha1_intermediate);
my $sha1_anchor_fingerprint = pem_cert_sha256($sha1_anchor);
my $sha256_via_intermediate_fingerprint =
    pem_cert_sha256($sha256_via_intermediate);
die "Fixture certificates cannot be identical"
    if $sha256_fingerprint eq $sha1_fingerprint;

# Both leaf certificates have the same RSA public key, subject, and test CA.
# The SHA-256 leaf uses RSA PKCS#1 v1.5 and so does the SHA-1 leaf.
# The latter matches the legacy sha1WithRSAEncryption case in issue #32223.
# With sigalgs_cert absent, the normal signature_algorithms list applies.
# The third case covers the RFC 9846 permitted SHA-1 fallback: the server has
# only the SHA-1 certificate, and the client explicitly advertised acceptance.
# SHA-1 is always listed at the lowest priority, after stronger schemes.
my @cases = (
    {
        cert => $sha256_cert,
        success => 1,
        allow_sha1 => 0,
        offered_fingerprint => $sha256_fingerprint,
        label => "TLS 1.3 offers supported RSA PKCS1 SHA-256 certificate"
    },
    {
        cert => $sha1_cert,
        success => 0,
        allow_sha1 => 0,
        offered_fingerprint => undef,
        label => "TLS 1.3 must not offer unadvertised RSA PKCS1 SHA-1 certificate"
    },
    {
        cert => $sha1_cert,
        success => 1,
        allow_sha1 => 1,
        offered_fingerprint => $sha1_fingerprint,
        label => "TLS 1.3 permits an explicitly advertised SHA-1 fallback"
    },
    {
        cert => $sha256_via_intermediate,
        chain => $sha1_intermediate_chain,
        success => 0,
        allow_sha1 => 0,
        offered_fingerprint => undef,
        label => "TLS 1.3 must reject unadvertised SHA-1-signed intermediate"
    },
    {
        cert => $sha256_via_intermediate,
        chain => $sha1_intermediate_chain,
        success => 1,
        allow_sha1 => 1,
        offered_fingerprint => $sha256_via_intermediate_fingerprint,
        intermediate_fingerprint => $sha1_intermediate_fingerprint,
        label => "TLS 1.3 allows explicitly advertised SHA-1 intermediate"
    },
    {
        cert => $sha256_cert,
        chain => $sha1_anchor,
        success => 1,
        allow_sha1 => 0,
        offered_fingerprint => $sha256_fingerprint,
        intermediate_fingerprint => $sha1_anchor_fingerprint,
        label => "TLS 1.3 permits self-signed SHA-1 trust-anchor signature"
    }
);


# Four certificate-order policy cases use OpenSSL's -xcert/-xkey/-xchain
# callback to present both otherwise-usable RSA chains. The SHA-256 leaf
# must win in both input orders, whether SHA-1 is advertised or not.
# The source patch ranks usable stronger chains before SHA-1 fallback.
for my $allow_sha1 (0, 1) {
    for my $weak_last (0, 1) {
        push @cases, {
            cert => $sha256_cert,
            success => 1,
            allow_sha1 => $allow_sha1,
            extra_cert_order => $weak_last
                ? [$sha256_cert, $sha1_cert]
                : [$sha1_cert, $sha256_cert],
            offered_fingerprint => $sha256_fingerprint,
            label => "TLS 1.3 prefers SHA-256: "
                . ($allow_sha1 ? "SHA-1 advertised" : "SHA-1 unadvertised")
                . ", " . ($weak_last ? "weak listed last" : "strong listed last")
        };
    }
}

# Additional coverage for the resolved-chain and effective-list paths.
push @cases, (
    {
        cert => $sha256_via_intermediate, auto_store => $sha1_intermediate_chain,
        success => 0, allow_sha1 => 0, offered_fingerprint => undef,
        label => "TLS 1.3 rejects automatically built unadvertised SHA-1 intermediate"
    },
    {
        cert => $sha256_via_intermediate, auto_store => $sha1_intermediate_chain,
        success => 1, allow_sha1 => 1,
        offered_fingerprint => $sha256_via_intermediate_fingerprint,
        intermediate_fingerprint => $sha1_intermediate_fingerprint,
        label => "TLS 1.3 allows advertised automatically built SHA-1 intermediate"
    },
    {
        cert => $sha1_cert, success => 1, allow_sha1 => 0,
        cert_sigalgs => [0x0401, 0x0201],
        offered_fingerprint => $sha1_fingerprint,
        label => "TLS 1.3 uses explicit SHA-1 certificate permission independently"
    },
    {
        cert => $sha1_cert, success => 0, allow_sha1 => 1,
        cert_sigalgs => [0x0401], offered_fingerprint => undef,
        label => "TLS 1.3 explicit certificate list overrides general SHA-1 permission"
    },
    {
        cert => $sha256_via_intermediate, chain => $sha1_intermediate_chain,
        success => 0, allow_sha1 => 1, cert_sigalgs => [0x0401],
        offered_fingerprint => undef,
        label => "TLS 1.3 applies explicit certificate list to SHA-1 intermediate"
    },
    {
        cert => $sha256_via_intermediate, chain => $sha1_intermediate_chain,
        success => 1, allow_sha1 => 0, cert_sigalgs => [0x0401, 0x0201],
        offered_fingerprint => $sha256_via_intermediate_fingerprint,
        intermediate_fingerprint => $sha1_intermediate_fingerprint,
        label => "TLS 1.3 permits intermediate using explicit SHA-1 certificate permission"
    }
);
for my $weak_last (0, 1) {
    push @cases, {
        cert => $sha256_cert, success => 1, allow_sha1 => 1,
        extra_cert_order => $weak_last
            ? [$sha256_cert, $sha1_cert] : [$sha1_cert, $sha256_cert],
        build_extra => 1, offered_fingerprint => $sha256_fingerprint,
        label => "TLS 1.3 prefers stronger automatically built candidate: "
            . ($weak_last ? "weak listed last" : "strong listed last")
    };
}
push @cases, (
    {
        cert => $sha1_cert, success => 1, allow_sha1 => 1,
        dual_cert => 1, offered_fingerprint => $ecdsa_fingerprint,
        sigalgs => "rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp256r1_sha256",
        label => "TLS 1.3 core selects non-SHA-1 chain across key types"
    },
    {
        cert => $sha256_cert, success => 1, allow_sha1 => 1,
        dual_cert => 1, offered_fingerprint => $sha256_fingerprint,
        sigalgs => "rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp256r1_sha256",
        label => "TLS 1.3 preserves algorithm preference among stronger chains"
    },
    {
        cert => $sha256_cert, chain => $sha1_anchor, success => 1,
        allow_sha1 => 0, cert_sigalgs => [0x0401],
        offered_fingerprint => $sha256_fingerprint,
        intermediate_fingerprint => $sha1_anchor_fingerprint,
        label => "TLS 1.3 explicit certificate list permits self-signed path start"
    },
    {
        cert => $sha256_cert, success => 1, allow_sha1 => 0,
        cert_sigalgs => [0x0401, 0x0201],
        extra_cert_order => [$sha256_cert, $sha1_cert],
        offered_fingerprint => $sha256_fingerprint,
        label => "TLS 1.3 still prefers strong chain when explicit list permits SHA-1"
    }
);

push @cases, (
    {
        cert => $sha256_via_intermediate, success => 1, allow_sha1 => 0,
        no_chain => 1, trust_intermediate => 1,
        offered_fingerprint => $sha256_via_intermediate_fingerprint,
        label => "TLS 1.3 verifies with an omitted non-self-signed SHA-1 trust anchor"
    },
    {
        cert => $sha256_cert, success => 1, allow_sha1 => 0,
        client_auth => 1, offered_fingerprint => $sha256_fingerprint,
        sigalgs => "rsa_pss_rsae_sha256:rsa_pkcs1_sha256:rsa_pss_pss_sha256",
        label => "TLS 1.3 preserves permitted client certificate-signature fallback"
    }
);

# Extract the additional CertificateEntry DER fingerprints without using
# the configured server cert names as a proxy for on-wire certificates.
sub trailing_cert_fingerprints {
    my ($data) = @_;
    my %hashes;
    while (length($data)) {
        die "Truncated TLS 1.3 CertificateEntry" if length($data) < 5;
        my ($high, $low) = unpack("Cn", substr($data, 0, 3));
        my $len = ($high << 16) | $low;
        die "Invalid TLS 1.3 CertificateEntry length"
            if $len == 0 || length($data) < $len + 5;
        my $extlen = unpack("n", substr($data, 3 + $len, 2));
        die "Invalid TLS 1.3 certificate extension length"
            if length($data) < $len + 5 + $extlen;
        $hashes{sha256_hex(substr($data, 3, $len))} = 1;
        $data = substr($data, $len + 5 + $extlen);
    }
    return %hashes;
}

# Real cryptography is required when chain building or peer verification is
# the subject of the test. TLSProxy's synthetic digest provider cannot do it.
sub read_text {
    my ($path) = @_;
    open my $fh, '<', $path or return "";
    local $/;
    return <$fh> // "";
}

sub trace_messages {
    my ($text, $direction, $name) = @_;
    my @messages;
    while ($text =~ /^\Q$direction\E[^\n]*Handshake[^\n]*, \Q$name\E\r?\n((?:[ \t]+[0-9a-fA-F ]+\r?\n)+)/mg) {
        my $hex = $1;
        $hex =~ s/\s//g;
        push @messages, pack("H*", $hex);
    }
    return @messages;
}

sub wire_extensions {
    my ($message, $offset) = @_;
    return {} if length($message) < $offset + 2;
    my $len = unpack("n", substr($message, $offset, 2));
    my $data = substr($message, $offset + 2);
    return {} unless length($data) == $len;
    my %extensions;
    while (length($data) >= 4) {
        my ($type, $size) = unpack("nn", $data);
        return {} if length($data) < 4 + $size || exists $extensions{$type};
        $extensions{$type} = substr($data, 4, $size);
        $data = substr($data, 4 + $size);
    }
    return length($data) ? {} : \%extensions;
}

sub native_case {
    my ($case) = @_;
    my $dir = tempdir(CLEANUP => 1);
    my @server = ("openssl", "s_server", "-provider", "default",
        "-accept", "127.0.0.1:0", "-naccept", "1", "-www", "-msg",
        "-state", "-max_protocol", "TLSv1.3", "-cert", $case->{cert},
        "-key", $key, "-cipher", 'DEFAULT:@SECLEVEL=0');
    if ($case->{build_extra}) {
        push @server, "-cert_chain", $ca, "-chainCAfile", $auto_store;
        for my $candidate (@{$case->{extra_cert_order}}) {
            push @server, "-xcert", $candidate, "-xkey", $key, "-xchain_build";
        }
    } elsif ($case->{no_chain}) {
        push @server, "-no-CAfile", "-no-CApath", "-no-CAstore";
    } else {
        push @server, "-cert_chain", $ca;
    }
    if ($case->{client_auth}) {
        push @server, "-Verify", "1", "-client_sigalgs", "rsa_pss_pss_sha256",
            "-CAfile", $client_root, "-no-CApath", "-no-CAstore", "-verify_return_error";
    }
    my $command = cmdstr(app(\@server, stdout => "$dir/server.out",
        stderr => "$dir/server.err"));
    my $pid = fork();
    die "Cannot fork s_server: $!" unless defined $pid;
    if (!$pid) {
        exec($command) or POSIX::_exit(127);
    }
    my ($port, $client_ok, $server_status, $failure);
    eval {
        local $SIG{ALRM} = sub { die "Native handshake timed out\n" };
        alarm 20;
        for (1..200) {
            my $output = read_text("$dir/server.out");
            ($port) = $output =~ /ACCEPT 127\.0\.0\.1:(\d+)/;
            last if $port;
            select undef, undef, undef, 0.05;
        }
        die "No loopback server port\n" unless $port;
        my $sigalgs = $case->{sigalgs}
            // "rsa_pss_rsae_sha256:rsa_pkcs1_sha256";
        $sigalgs .= ":rsa_pkcs1_sha1" if $case->{allow_sha1};
        my @client = ("openssl", "s_client", "-provider", "default",
            "-connect", "127.0.0.1:$port", "-max_protocol", "TLSv1.3",
            "-min_protocol", $case->{allow_sha1} ? "TLSv1.2" : "TLSv1.3",
            "-sigalgs", $sigalgs, "-cipher", 'DEFAULT:@SECLEVEL=0',
            "-msg", "-showcerts", "-ign_eof", "-verify_return_error",
            "-no-CApath", "-no-CAstore", "-CAfile",
            $case->{trust_intermediate} ? $sha1_intermediate : $auto_store);
        push @client, "-partial_chain" if $case->{trust_intermediate};
        push @client, "-cert", $client_pss_cert, "-key", $client_pss_key,
            "-cert_chain", $client_root if $case->{client_auth};
        open my $request, '>', "$dir/request" or die $!;
        print $request "GET / HTTP/1.0\r\n\r\n";
        close $request;
        $client_ok = run(app(\@client, stdin => "$dir/request",
            stdout => "$dir/client.out", stderr => "$dir/client.err"));
        waitpid($pid, 0);
        $server_status = $?;
        alarm 0;
    };
    $failure = $@;
    alarm 0;
    if (!defined $server_status) {
        kill 'TERM', $pid;
        waitpid($pid, 0);
    }
    my $client = read_text("$dir/client.out");
    my $server = read_text("$dir/server.out");
    my $errors = read_text("$dir/client.err") . read_text("$dir/server.err");
    my @hello = trace_messages($client, ">>>", "ClientHello");
    my $hello_ok = 0;
    if (@hello == 1 && length($hello[0]) > 39) {
        my $h = $hello[0];
        my $pos = 39 + unpack("C", substr($h, 38, 1));
        $pos += 2 + unpack("n", substr($h, $pos, 2));
        $pos += 1 + unpack("C", substr($h, $pos, 1));
        my $extensions = wire_extensions($h, $pos);
        my $algs = $extensions->{13} // "";
        if (length($algs) >= 2
            && unpack("n", substr($algs, 0, 2)) == length($algs) - 2) {
            my @ids = unpack("n*", substr($algs, 2));
            $hello_ok = !exists($extensions->{50})
                && !!(grep { $_ == 0x0201 } @ids) == !!$case->{allow_sha1}
                && (grep { $_ == 0x0804 } @ids)
                && (grep { $_ == 0x0401 } @ids);
        }
    }
    my @certs = trace_messages($client, "<<<", "Certificate");
    my %wire;
    my $first_fingerprint = "";
    if (@certs == 1 && length($certs[0]) > 8) {
        my $offset = 8 + unpack("C", substr($certs[0], 4, 1));
        my $entries = substr($certs[0], $offset);
        %wire = trailing_cert_fingerprints($entries);
        my ($high, $low) = unpack("Cn", substr($entries, 0, 3));
        $first_fingerprint = sha256_hex(substr($entries, 3, ($high << 16) | $low));
    }
    my $wire_ok = $first_fingerprint eq $case->{offered_fingerprint};
    $wire_ok &&= keys(%wire) == 1 if $case->{no_chain};
    my $auth_ok = 1;
    if ($case->{client_auth}) {
        my @requests = trace_messages($client, "<<<", "CertificateRequest");
        my @client_certs = trace_messages($server, "<<<", "Certificate");
        $auth_ok = @requests == 1 && @client_certs == 1;
        if ($auth_ok) {
            my $ext = wire_extensions($requests[0],
                5 + unpack("C", substr($requests[0], 4, 1)));
            my $offset = 8 + unpack("C", substr($client_certs[0], 4, 1));
            my %client_wire = trailing_cert_fingerprints(
                substr($client_certs[0], $offset));
            $auth_ok = !exists($ext->{50})
                && ($ext->{13} // "") eq pack("nn", 2, 0x0809)
                && exists($client_wire{$client_pss_fingerprint});
        }
    }
    # A returned HTTP page and server-issued ticket prove the server accepted
    # Finished (and, for mutual authentication, verified the client chain).
    my @tickets = trace_messages($client, "<<<", "NewSessionTicket");
    my $ok = !$failure && $client_ok && defined($server_status)
        && $server_status == 0 && $hello_ok && $wire_ok && $auth_ok
        && @tickets && $client =~ /HTTP\/1\.0 200 ok/
        && $client =~ /Protocol\s*:\s*TLSv1\.3/
        && $errors !~ /(?:alert.*fatal|verify error:)/i;
    diag("native default-provider case failed: $failure\n$errors\n"
        . "client_ok=" . ($client_ok // 0) . "; hello=$hello_ok; wire=$wire_ok; auth=$auth_ok; tickets="
        . scalar(@tickets) . "; server_status=" . ($server_status // -1)) unless $ok;
    return $ok;
}

plan tests => scalar @cases;

for my $case (@cases) {
    if ($case->{build_extra} || $case->{trust_intermediate} || $case->{client_auth}) {
        ok(native_case($case), $case->{label});
        next;
    }
    my $observed_expected_hello = 0;
    my %offered_server_certs;
    my %offered_intermediates;
    my %offered_client_certs;
    my $observed_cert_request = 0;

    my $filter = sub {
        my $proxy = shift;

        foreach my $message (@{$proxy->message_list}) {
            if ($proxy->flight == 0
                && $message->mt == TLSProxy::Message::MT_CLIENT_HELLO) {
                my $extensions = $message->extension_data;
                my $sigalg_type = TLSProxy::Message::EXT_SIG_ALGS;
                my $cert_type = TLSProxy::Message::EXT_SIG_ALGS_CERT;

                if (defined($case->{cert_sigalgs})) {
                    my @cert_algs = @{$case->{cert_sigalgs}};
                    my $cert_wire = pack("n", 2 * scalar @cert_algs)
                        . pack("n*", @cert_algs);
                    $extensions->{$cert_type} = $cert_wire;
                    $message->repack();
                    next unless $message->extension_data->{$cert_type} eq $cert_wire;
                } else {
                    next if exists $extensions->{$cert_type};
                }
                next unless exists $extensions->{$sigalg_type};

                my $wire = $extensions->{$sigalg_type};
                next if length($wire) < 4;
                my $bytes = unpack("n", substr($wire, 0, 2));
                next unless $bytes == length($wire) - 2 && $bytes % 2 == 0;
                my @algs = unpack("n*", substr($wire, 2));
                my $has_sha1 = grep {
                    $_ == 0x0201 || $_ == 0x0202 || $_ == 0x0203
                } @algs;
                my $has_pss256 = grep { $_ == 0x0804 } @algs;
                my $has_rsa256 = grep { $_ == 0x0401 } @algs;
                $observed_expected_hello =
                    (!!$has_sha1 == !!$case->{allow_sha1})
                    && $has_pss256 && $has_rsa256;
            }

            if ($case->{client_auth} && $message->server()
                && $message->mt == TLSProxy::Message::MT_CERTIFICATE_REQUEST) {
                my $extensions = $message->extension_data;
                my $alg = TLSProxy::Message::EXT_SIG_ALGS;
                my $cert_alg = TLSProxy::Message::EXT_SIG_ALGS_CERT;
                $observed_cert_request = !exists($extensions->{$cert_alg})
                    && exists($extensions->{$alg})
                    && $extensions->{$alg} eq pack("nn", 2, 0x0809);
            }
            if ($case->{client_auth} && !$message->server()
                && $message->mt == TLSProxy::Message::MT_CERTIFICATE) {
                my $der = $message->first_certificate();
                $offered_client_certs{sha256_hex($der)} = 1
                    if defined($der) && length($der);
            }

            # TLSProxy decodes the test-provider's TLS 1.3 encrypted flight.
            # Record actual DER bytes emitted by the *server*, not a local
            # configured filename or the ultimate handshake exit status.
            if ($message->server()
                && $message->mt == TLSProxy::Message::MT_CERTIFICATE) {
                my $der = $message->first_certificate();
                if (defined($der) && length($der)) {
                    $offered_server_certs{sha256_hex($der)} = 1;
                    my %rest = trailing_cert_fingerprints(
                        $message->remaining_certdata());
                    $offered_intermediates{$_} = 1 for keys %rest;
                }
            }
        }
    };

    my $proxy = TLSProxy::Proxy->new(
        $filter,
        cmdstr(app(["openssl"]), display => 1),
        $case->{cert},
        (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE}),
        0  # IPv4 loopback; no external target.
    );

    $proxy->clear();
    my $chain = $case->{chain} // $ca;
    my $extra_cert_args = "";
    if (defined($case->{extra_cert_order})) {
        # s_server's -xcert/-xkey/-xchain entries use the native certificate
        # callback; identical test key and issuer make signing algorithm the
        # only intentional distinction between these two candidates.
        for my $candidate (@{$case->{extra_cert_order}}) {
            $extra_cert_args .= " -xcert $candidate -xkey $key";
            $extra_cert_args .= $case->{build_extra}
                ? " -xchain_build" : " -xchain $ca";
        }
    }
    my $chain_args = $case->{no_chain}
        ? " -no-CAfile -no-CApath -no-CAstore"
        : defined($case->{auto_store}) ? " -chainCAfile $case->{auto_store}"
        : " -cert_chain $chain";
    $chain_args .= " -chainCAfile $auto_store" if $case->{build_extra};
    my $dual_args = $case->{dual_cert}
        ? " -dcert $ecdsa_cert -dkey $ecdsa_key -dcert_chain $root" : "";
    my $auth_args = $case->{client_auth}
        ? " -Verify 1 -client_sigalgs rsa_pss_pss_sha256 -CAfile $root"
            . " -no-CApath -no-CAstore -verify_return_error"
        : "";
    $proxy->serverflags(
        " -key $key -key2 $key$chain_args$extra_cert_args$dual_args$auth_args");
    $proxy->ciphers("DEFAULT:\@SECLEVEL=0");
    my $sigalgs = $case->{sigalgs} // "rsa_pss_rsae_sha256:rsa_pkcs1_sha256";
    $sigalgs .= ":rsa_pkcs1_sha1" if $case->{allow_sha1};

    # OpenSSL does not emit SHA-1 signature_algorithms when TLS 1.3 is the
    # configured *minimum* version (tls12_sigalg_allowed). To test a client
    # that explicitly allows the legacy fallback, permit TLS 1.2 as the
    # minimum only in that case. The TLSProxy server still negotiates TLS
    # 1.3, which we assert below. Other cases force TLS 1.3 throughout.
    my $min_protocol = $case->{allow_sha1}
        ? "-min_protocol TLSv1.2" : "-tls1_3";
    my $client_extra = $case->{client_auth}
        ? " -cert $client_pss_cert -key $client_pss_key -cert_chain $root" : "";
    $client_extra .= " -CAfile $sha1_intermediate -partial_chain"
        . " -verify_return_error -no-CApath -no-CAstore"
        if $case->{trust_intermediate};
    $proxy->clientflags(
        "$min_protocol -sigalgs $sigalgs -cipher DEFAULT:\@SECLEVEL=0$client_extra");

    my $proxy_started = $proxy->start();
    my $observed_success = TLSProxy::Message->success()
        && $proxy->handshake_complete();
    my $negotiated_tls13 = TLSProxy::Proxy->is_tls13();
    # The reject-before-ServerHello case may correctly have no negotiated
    # protocol. Successful cases MUST prove this was TLS 1.3, not TLS 1.2.
    my $version_is_expected = !$case->{success} || $negotiated_tls13;
    my @offered = sort keys %offered_server_certs;
    my @intermediates = sort keys %offered_intermediates;
    my $intermediate_is_expected =
        defined($case->{intermediate_fingerprint})
        ? exists $offered_intermediates{$case->{intermediate_fingerprint}}
        : !defined($case->{offered_fingerprint}) ? @intermediates == 0 : 1;
    $intermediate_is_expected &&= @intermediates == 0 if $case->{no_chain};
    my $client_is_expected = !$case->{client_auth}
        || ($observed_cert_request && keys(%offered_client_certs) == 1
            && exists($offered_client_certs{$client_pss_fingerprint}));
    my $wire_is_expected = defined($case->{offered_fingerprint})
        ? (@offered == 1 && $offered[0] eq $case->{offered_fingerprint})
        : (@offered == 0);

    unless ($proxy_started && $observed_expected_hello
            && $version_is_expected && $wire_is_expected
            && $intermediate_is_expected && $client_is_expected
            && (!!$observed_success == !!$case->{success})) {
        diag("proxy_started=" . (!!$proxy_started)
            . "; expected_client_hello=" . (!!$observed_expected_hello)
            . "; negotiated_tls13=" . (!!$negotiated_tls13)
            . "; handshake_success=" . (!!$observed_success)
            . "; wire_fingerprints=[" . join(",", @offered) . "]"
            . "; intermediates=[" . join(",", @intermediates) . "]"
            . "; client_request=" . (!!$observed_cert_request)
            . "; client_wire=[" . join(",", sort keys %offered_client_certs) . "]"
            . "; expected_intermediate="
            . ($case->{intermediate_fingerprint} // "none")
            . "; expected="
            . ($case->{offered_fingerprint} // "no_server_cert"));
    }

    ok($proxy_started && $observed_expected_hello
        && $version_is_expected && $wire_is_expected
        && $intermediate_is_expected && $client_is_expected
        && (!!$observed_success == !!$case->{success}),
        $case->{label});
}
