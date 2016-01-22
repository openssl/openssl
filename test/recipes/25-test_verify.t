#! /usr/bin/perl

use strict;
use warnings;

use File::Spec::Functions qw/canonpath/;
use OpenSSL::Test qw/:DEFAULT top_dir top_file/;

setup("test_verify");

sub verify {
    my ($cert, $vname, $trusted, $untrusted, @opts) = @_;
    my @args = qw(openssl verify -verify_name);
    my @path = qw(test certs);
    push(@args, "$vname", @opts);
    for (@$trusted) { push(@args, "-trusted", top_dir(@path, "$_.pem")) }
    for (@$untrusted) { push(@args, "-untrusted", top_dir(@path, "$_.pem")) }
    push(@args, top_dir(@path, "$cert.pem"));
    run(app([@args]));
}

plan tests => 29;

# Canonical success
ok(verify("ee-cert", "ssl_server", ["root-cert"], ["ca-cert"]),
   "verify valid chain");

# Root CA variants
ok(verify("ee-cert", "ssl_server", [qw(root-nonca)], [qw(ca-cert)]),
   "Trusted certs not subject to CA:true checks");
ok(!verify("ee-cert", "ssl_server", [qw(root-cert2)], [qw(ca-cert)]),
   "fail wrong root key");
ok(!verify("ee-cert", "ssl_server", [qw(root-name2)], [qw(ca-cert)]),
   "fail wrong root DN");
ok(verify("ee-cert", "ssl_server", [qw(root+serverAuth)], [qw(ca-cert)]),
   "accept right EKU");
ok(!verify("ee-cert", "ssl_server", [qw(root-serverAuth)], [qw(ca-cert)]),
   "fail rejected EKU");
ok(!verify("ee-cert", "ssl_server", [qw(root+clientAuth)], [qw(ca-cert)]),
   "fail wrong EKU");

# CA variants
ok(!verify("ee-cert", "ssl_server", [qw(root-cert)], [qw(ca-nonca)]),
   "fail non-CA");
ok(!verify("ee-cert", "ssl_server", [qw(root-cert)], [qw(ca-cert2)]),
   "fail wrong CA key");
ok(!verify("ee-cert", "ssl_server", [qw(root-cert)], [qw(ca-name2)]),
   "fail wrong CA DN");
ok(!verify("ee-cert", "ssl_server", [qw(root-cert)], [qw(ca-root2)]),
   "fail wrong CA issuer");
ok(!verify("ee-cert", "ssl_server", [], [qw(ca-cert)], "-partial_chain"),
   "fail untrusted partial");
ok(!verify("ee-cert", "ssl_server", [], [qw(ca+serverAuth)], "-partial_chain"),
   "fail untrusted EKU partial");
ok(verify("ee-cert", "ssl_server", [qw(ca+serverAuth)], [], "-partial_chain"),
   "accept trusted EKU partial");
ok(!verify("ee-cert", "ssl_server", [qw(ca-serverAuth)], [], "-partial_chain"),
   "fail rejected EKU partial");
ok(!verify("ee-cert", "ssl_server", [qw(ca+clientAuth)], [], "-partial_chain"),
   "fail wrong EKU partial");

# EE variants
ok(verify("ee-client", "ssl_client", [qw(root-cert)], [qw(ca-cert)]),
   "accept client cert");
ok(!verify("ee-client", "ssl_server", [qw(root-cert)], [qw(ca-cert)]),
   "fail wrong leaf purpose");
ok(!verify("ee-cert", "ssl_client", [qw(root-cert)], [qw(ca-cert)]),
   "fail wrong leaf purpose");
ok(!verify("ee-cert2", "ssl_server", [qw(root-cert)], [qw(ca-cert)]),
   "fail wrong CA key");
ok(!verify("ee-name2", "ssl_server", [qw(root-cert)], [qw(ca-cert)]),
   "fail wrong CA name");
ok(!verify("ee-expired", "ssl_server", [qw(root-cert)], [qw(ca-cert)]),
   "fail expired leaf");
ok(verify("ee-cert", "ssl_server", [qw(ee-cert)], [], "-partial_chain"),
   "accept last-resort direct leaf match");
ok(verify("ee-client", "ssl_client", [qw(ee-client)], [], "-partial_chain"),
   "accept last-resort direct leaf match");
ok(!verify("ee-cert", "ssl_server", [qw(ee-client)], [], "-partial_chain"),
   "fail last-resort direct leaf non-match");
ok(verify("ee-cert", "ssl_server", [qw(ee+serverAuth)], [], "-partial_chain"),
   "accept direct match with trusted EKU");
ok(!verify("ee-cert", "ssl_server", [qw(ee-serverAuth)], [], "-partial_chain"),
   "reject direct match with rejected EKU");
ok(verify("ee-client", "ssl_client", [qw(ee+clientAuth)], [], "-partial_chain"),
   "accept direct match with trusted EKU");
ok(!verify("ee-client", "ssl_client", [qw(ee-clientAuth)], [], "-partial_chain"),
   "reject direct match with rejected EKU");
