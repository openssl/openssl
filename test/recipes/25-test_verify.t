#! /usr/bin/perl

use strict;
use warnings;

use File::Spec::Functions qw/canonpath/;
use OpenSSL::Test qw/:DEFAULT top_file/;

setup("test_verify");

sub verify {
    my ($cert, $purpose, $trusted, $untrusted, @opts) = @_;
    my @args = qw(openssl verify -purpose);
    my @path = qw(test certs);
    push(@args, "$purpose", @opts);
    for (@$trusted) { push(@args, "-trusted", top_file(@path, "$_.pem")) }
    for (@$untrusted) { push(@args, "-untrusted", top_file(@path, "$_.pem")) }
    push(@args, top_file(@path, "$cert.pem"));
    run(app([@args]));
}

plan tests => 38;

# Canonical success
ok(verify("ee-cert", "sslserver", ["root-cert"], ["ca-cert"]),
   "verify valid chain");

# Root CA variants
ok(!verify("ee-cert", "sslserver", [qw(root-nonca)], [qw(ca-cert)]),
   "Trusted CA certs now subject to CA:true checks");
ok(!verify("ee-cert", "sslserver", [qw(root-cert2)], [qw(ca-cert)]),
   "fail wrong root key");
ok(!verify("ee-cert", "sslserver", [qw(root-name2)], [qw(ca-cert)]),
   "fail wrong root DN");
ok(verify("ee-cert", "sslserver", [qw(root+serverAuth)], [qw(ca-cert)]),
   "accept right EKU");
ok(verify("ee-cert", "sslserver", [qw(root+anyEKU)], [qw(ca-cert)]),
   "accept anyEKU");
ok(!verify("ee-cert", "sslserver", [qw(root-serverAuth)], [qw(ca-cert)]),
   "fail rejected EKU");
ok(!verify("ee-cert", "sslserver", [qw(root-anyEKU)], [qw(ca-cert)]),
   "fail rejected anyEKU");
ok(!verify("ee-cert", "sslserver", [qw(root+clientAuth)], [qw(ca-cert)]),
   "fail wrong EKU");

# Check that trusted-first is on by setting up paths to different roots
# depending on whether the intermediate is the trusted or untrusted one.
#
ok(verify("ee-cert", "sslserver", [qw(root-serverAuth root-cert2 ca-root2)],
          [qw(ca-cert)]),
   "verify trusted-first path");
ok(verify("ee-cert", "sslserver", [qw(root-cert root2+serverAuth ca-root2)],
          [qw(ca-cert)]),
   "verify trusted-first path right EKU");
ok(!verify("ee-cert", "sslserver", [qw(root-cert root2-serverAuth ca-root2)],
           [qw(ca-cert)]),
   "fail trusted-first path rejected EKU");
ok(!verify("ee-cert", "sslserver", [qw(root-cert root2+clientAuth ca-root2)],
           [qw(ca-cert)]),
   "fail trusted-first path wrong EKU");

# CA variants
ok(!verify("ee-cert", "sslserver", [qw(root-cert)], [qw(ca-nonca)]),
   "fail non-CA");
ok(!verify("ee-cert", "sslserver", [qw(root-cert)], [qw(ca-cert2)]),
   "fail wrong CA key");
ok(!verify("ee-cert", "sslserver", [qw(root-cert)], [qw(ca-name2)]),
   "fail wrong CA DN");
ok(!verify("ee-cert", "sslserver", [qw(root-cert)], [qw(ca-root2)]),
   "fail wrong CA issuer");
ok(!verify("ee-cert", "sslserver", [], [qw(ca-cert)], "-partial_chain"),
   "fail untrusted partial");
ok(!verify("ee-cert", "sslserver", [], [qw(ca+serverAuth)], "-partial_chain"),
   "fail untrusted EKU partial");
ok(verify("ee-cert", "sslserver", [qw(ca+serverAuth)], [], "-partial_chain"),
   "accept trusted EKU partial");
ok(!verify("ee-cert", "sslserver", [qw(ca-serverAuth)], [], "-partial_chain"),
   "fail rejected EKU partial");
ok(!verify("ee-cert", "sslserver", [qw(ca+clientAuth)], [], "-partial_chain"),
   "fail wrong EKU partial");

# We now test auxiliary trust even for intermediate trusted certs without
# -partial_chain.  Note that "-trusted_first" is now always on and cannot
# be disabled.
ok(verify("ee-cert", "sslserver", [qw(root-cert ca+serverAuth)], [qw(ca-cert)]),
   "accept trusted EKU");
ok(!verify("ee-cert", "sslserver", [qw(root-cert ca-serverAuth)], [qw(ca-cert)]),
   "fail rejected EKU");
ok(!verify("ee-cert", "sslserver", [qw(root-cert ca+clientAuth)], [qw(ca-cert)]),
   "fail wrong EKU");

# EE variants
ok(verify("ee-client", "sslclient", [qw(root-cert)], [qw(ca-cert)]),
   "accept client cert");
ok(!verify("ee-client", "sslserver", [qw(root-cert)], [qw(ca-cert)]),
   "fail wrong leaf purpose");
ok(!verify("ee-cert", "sslclient", [qw(root-cert)], [qw(ca-cert)]),
   "fail wrong leaf purpose");
ok(!verify("ee-cert2", "sslserver", [qw(root-cert)], [qw(ca-cert)]),
   "fail wrong CA key");
ok(!verify("ee-name2", "sslserver", [qw(root-cert)], [qw(ca-cert)]),
   "fail wrong CA name");
ok(!verify("ee-expired", "sslserver", [qw(root-cert)], [qw(ca-cert)]),
   "fail expired leaf");
ok(verify("ee-cert", "sslserver", [qw(ee-cert)], [], "-partial_chain"),
   "accept last-resort direct leaf match");
ok(verify("ee-client", "sslclient", [qw(ee-client)], [], "-partial_chain"),
   "accept last-resort direct leaf match");
ok(!verify("ee-cert", "sslserver", [qw(ee-client)], [], "-partial_chain"),
   "fail last-resort direct leaf non-match");
ok(verify("ee-cert", "sslserver", [qw(ee+serverAuth)], [], "-partial_chain"),
   "accept direct match with trusted EKU");
ok(!verify("ee-cert", "sslserver", [qw(ee-serverAuth)], [], "-partial_chain"),
   "reject direct match with rejected EKU");
ok(verify("ee-client", "sslclient", [qw(ee+clientAuth)], [], "-partial_chain"),
   "accept direct match with trusted EKU");
ok(!verify("ee-client", "sslclient", [qw(ee-clientAuth)], [], "-partial_chain"),
   "reject direct match with rejected EKU");
