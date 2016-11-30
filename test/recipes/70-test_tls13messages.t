#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file srctop_dir bldtop_dir/;
use OpenSSL::Test::Utils;
use File::Temp qw(tempfile);
use TLSProxy::Proxy;

my $test_name;

# This block needs to run before 'use lib srctop_dir' directives.
BEGIN {
    $test_name = "test_tls13messages";
    OpenSSL::Test::setup($test_name);
}

use lib srctop_dir("test", "recipes");

use recipes::checkhandshake qw(checkhandshake @handmessages @extensions);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS|MSWin32)$/;

plan skip_all => "$test_name needs the dynamic engine feature enabled"
    if disabled("engine") || disabled("dynamic-engine");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs TLSv1.3 enabled"
    if disabled("tls1_3");

$ENV{OPENSSL_ia32cap} = '~0x200000200000000';
$ENV{CTLOG_FILE} = srctop_file("test", "ct", "log_list.conf");


@handmessages = (
    [TLSProxy::Message::MT_CLIENT_HELLO,
        recipes::checkhandshake::ALL_HANDSHAKES],
    [TLSProxy::Message::MT_SERVER_HELLO,
        recipes::checkhandshake::ALL_HANDSHAKES],
    [TLSProxy::Message::MT_ENCRYPTED_EXTENSIONS,
        recipes::checkhandshake::ALL_HANDSHAKES],
    [TLSProxy::Message::MT_CERTIFICATE_REQUEST,
        recipes::checkhandshake::CLIENT_AUTH_HANDSHAKE],
    [TLSProxy::Message::MT_CERTIFICATE,
        recipes::checkhandshake::ALL_HANDSHAKES & ~recipes::checkhandshake::RESUME_HANDSHAKE],
    [TLSProxy::Message::MT_CERTIFICATE_STATUS,
        recipes::checkhandshake::OCSP_HANDSHAKE],
    [TLSProxy::Message::MT_FINISHED,
        recipes::checkhandshake::ALL_HANDSHAKES],
    [TLSProxy::Message::MT_CERTIFICATE,
        recipes::checkhandshake::CLIENT_AUTH_HANDSHAKE],
    [TLSProxy::Message::MT_CERTIFICATE_VERIFY,
        recipes::checkhandshake::CLIENT_AUTH_HANDSHAKE],
    [TLSProxy::Message::MT_FINISHED,
        recipes::checkhandshake::ALL_HANDSHAKES],
    [0, 0]
);

@extensions = (
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SERVER_NAME,
        recipes::checkhandshake::SERVER_NAME_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_STATUS_REQUEST,
        recipes::checkhandshake::STATUS_REQUEST_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SUPPORTED_GROUPS,
        recipes::checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_EC_POINT_FORMATS,
        recipes::checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SIG_ALGS,
        recipes::checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_ALPN,
        recipes::checkhandshake::ALPN_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SCT,
        recipes::checkhandshake::SCT_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_ENCRYPT_THEN_MAC,
        recipes::checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_EXTENDED_MASTER_SECRET,
        recipes::checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SESSION_TICKET,
        recipes::checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_KEY_SHARE,
        recipes::checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SUPPORTED_VERSIONS,
        recipes::checkhandshake::DEFAULT_EXTENSIONS],

    [TLSProxy::Message::MT_SERVER_HELLO, TLSProxy::Message::EXT_KEY_SHARE,
        recipes::checkhandshake::DEFAULT_EXTENSIONS],

    [TLSProxy::Message::MT_ENCRYPTED_EXTENSIONS, TLSProxy::Message::EXT_SERVER_NAME,
        recipes::checkhandshake::SERVER_NAME_SRV_EXTENSION],
    [TLSProxy::Message::MT_ENCRYPTED_EXTENSIONS, TLSProxy::Message::EXT_STATUS_REQUEST,
        recipes::checkhandshake::STATUS_REQUEST_SRV_EXTENSION],
    [TLSProxy::Message::MT_ENCRYPTED_EXTENSIONS, TLSProxy::Message::EXT_ALPN,
        recipes::checkhandshake::ALPN_SRV_EXTENSION],
    [0,0,0]
);

my $proxy = TLSProxy::Proxy->new(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

#Test 1: Check we get all the right messages for a default handshake
(undef, my $session) = tempfile();
#$proxy->serverconnects(2);
$proxy->clientflags("-sess_out ".$session);
$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
plan tests => 12;
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
               recipes::checkhandshake::DEFAULT_EXTENSIONS,
               "Default handshake test");

#TODO(TLS1.3): Test temporarily disabled until we implement TLS1.3 resumption
#Test 2: Resumption handshake
#$proxy->clearClient();
#$proxy->clientflags("-sess_in ".$session);
#$proxy->clientstart();
#checkmessages(RESUME_HANDSHAKE, "Resumption handshake test");
unlink $session;

#Test 3: A status_request handshake (client request only)
$proxy->clear();
$proxy->clientflags("-status");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
              recipes::checkhandshake::DEFAULT_EXTENSIONS
              | recipes::checkhandshake::STATUS_REQUEST_CLI_EXTENSION,
              "status_request handshake test (client)");

#Test 4: A status_request handshake (server support only)
$proxy->clear();
$proxy->serverflags("-status_file "
                    .srctop_file("test", "recipes", "ocsp-response.der"));
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
               recipes::checkhandshake::DEFAULT_EXTENSIONS,
              "status_request handshake test (server)");

#Test 5: A status_request handshake (client and server)
#TODO(TLS1.3): TLS1.3 doesn't actually have CertificateStatus messages. This is
#a temporary test until such time as we do proper TLS1.3 style certificate
#status
$proxy->clear();
$proxy->clientflags("-status");
$proxy->serverflags("-status_file "
                    .srctop_file("test", "recipes", "ocsp-response.der"));
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::OCSP_HANDSHAKE,
              recipes::checkhandshake::DEFAULT_EXTENSIONS
              | recipes::checkhandshake::STATUS_REQUEST_CLI_EXTENSION
              | recipes::checkhandshake::STATUS_REQUEST_SRV_EXTENSION,
              "status_request handshake test");

#Test 6: A client auth handshake
$proxy->clear();
$proxy->clientflags("-cert ".srctop_file("apps", "server.pem"));
$proxy->serverflags("-Verify 5");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::CLIENT_AUTH_HANDSHAKE,
               recipes::checkhandshake::DEFAULT_EXTENSIONS,
              "Client auth handshake test");

#Test 7: Server name handshake (client request only)
$proxy->clear();
$proxy->clientflags("-servername testhost");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
               recipes::checkhandshake::DEFAULT_EXTENSIONS
               | recipes::checkhandshake::SERVER_NAME_CLI_EXTENSION,
              "Server name handshake test (client)");

#Test 8: Server name handshake (server support only)
$proxy->clear();
$proxy->serverflags("-servername testhost");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
               recipes::checkhandshake::DEFAULT_EXTENSIONS,
              "Server name handshake test (server)");

#Test 9: Server name handshake (client and server)
$proxy->clear();
$proxy->clientflags("-servername testhost");
$proxy->serverflags("-servername testhost");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
              recipes::checkhandshake::DEFAULT_EXTENSIONS
              | recipes::checkhandshake::SERVER_NAME_CLI_EXTENSION
              | recipes::checkhandshake::SERVER_NAME_SRV_EXTENSION,
              "Server name handshake test");

#Test 10: ALPN handshake (client request only)
$proxy->clear();
$proxy->clientflags("-alpn test");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
               recipes::checkhandshake::DEFAULT_EXTENSIONS
               | recipes::checkhandshake::ALPN_CLI_EXTENSION,
              "ALPN handshake test (client)");

#Test 11: ALPN handshake (server support only)
$proxy->clear();
$proxy->serverflags("-alpn test");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
               recipes::checkhandshake::DEFAULT_EXTENSIONS,
              "ALPN handshake test (server)");

#Test 12: ALPN handshake (client and server)
$proxy->clear();
$proxy->clientflags("-alpn test");
$proxy->serverflags("-alpn test");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
              recipes::checkhandshake::DEFAULT_EXTENSIONS
              | recipes::checkhandshake::ALPN_CLI_EXTENSION
              | recipes::checkhandshake::ALPN_SRV_EXTENSION,
              "ALPN handshake test");

#Test 13: SCT handshake (client request only)
#TODO(TLS1.3): This only checks that the client side extension appears. The
#SCT extension is unusual in that we have no built-in server side implementation
#The server side implementation can nomrally be added using the custom
#extensions framework (e.g. by using the "-serverinfo" s_server option). However
#currently we only support <= TLS1.2 for custom extensions because the existing
#framework and API has no knowledge of the TLS1.3 messages
$proxy->clear();
#Note: -ct also sends status_request
$proxy->clientflags("-ct");
$proxy->serverflags("-status_file "
                    .srctop_file("test", "recipes", "ocsp-response.der"));
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::OCSP_HANDSHAKE,
              recipes::checkhandshake::DEFAULT_EXTENSIONS
              | recipes::checkhandshake::SCT_CLI_EXTENSION
              | recipes::checkhandshake::STATUS_REQUEST_CLI_EXTENSION
              | recipes::checkhandshake::STATUS_REQUEST_SRV_EXTENSION,
              "SCT handshake test");
