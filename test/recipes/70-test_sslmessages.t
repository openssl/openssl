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
    $test_name = "test_sslmessages";
    OpenSSL::Test::setup($test_name);
}
use lib srctop_dir("test");

use recipes::checkhandshake qw(checkhandshake @handmessages @extensions);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS|MSWin32)$/;

plan skip_all => "$test_name needs the dynamic engine feature enabled"
    if disabled("engine") || disabled("dynamic-engine");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs TLS enabled"
    if alldisabled(available_protocols("tls"));

$ENV{OPENSSL_ia32cap} = '~0x200000200000000';
$ENV{CTLOG_FILE} = srctop_file("test", "ct", "log_list.conf");

my $proxy = TLSProxy::Proxy->new(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

@handmessages = (
    [TLSProxy::Message::MT_CLIENT_HELLO,
        recipes::checkhandshake::ALL_HANDSHAKES],
    [TLSProxy::Message::MT_SERVER_HELLO,
        recipes::checkhandshake::ALL_HANDSHAKES],
    [TLSProxy::Message::MT_CERTIFICATE,
        recipes::checkhandshake::ALL_HANDSHAKES
        & ~recipes::checkhandshake::RESUME_HANDSHAKE],
    [TLSProxy::Message::MT_CERTIFICATE_STATUS,
        recipes::checkhandshake::OCSP_HANDSHAKE],
    #ServerKeyExchange handshakes not currently supported by TLSProxy
    [TLSProxy::Message::MT_CERTIFICATE_REQUEST,
        recipes::checkhandshake::CLIENT_AUTH_HANDSHAKE],
    [TLSProxy::Message::MT_SERVER_HELLO_DONE,
        recipes::checkhandshake::ALL_HANDSHAKES
        & ~recipes::checkhandshake::RESUME_HANDSHAKE],
    [TLSProxy::Message::MT_CERTIFICATE,
        recipes::checkhandshake::CLIENT_AUTH_HANDSHAKE],
    [TLSProxy::Message::MT_CLIENT_KEY_EXCHANGE,
        recipes::checkhandshake::ALL_HANDSHAKES
        & ~recipes::checkhandshake::RESUME_HANDSHAKE],
    [TLSProxy::Message::MT_CERTIFICATE_VERIFY,
        recipes::checkhandshake::CLIENT_AUTH_HANDSHAKE],
    [TLSProxy::Message::MT_NEXT_PROTO,
        recipes::checkhandshake::NPN_HANDSHAKE],
    [TLSProxy::Message::MT_FINISHED,
        recipes::checkhandshake::ALL_HANDSHAKES],
    [TLSProxy::Message::MT_NEW_SESSION_TICKET,
        recipes::checkhandshake::ALL_HANDSHAKES
        & ~recipes::checkhandshake::RESUME_HANDSHAKE],
    [TLSProxy::Message::MT_FINISHED,
        recipes::checkhandshake::ALL_HANDSHAKES],
    [TLSProxy::Message::MT_CLIENT_HELLO,
        recipes::checkhandshake::RENEG_HANDSHAKE],
    [TLSProxy::Message::MT_SERVER_HELLO,
        recipes::checkhandshake::RENEG_HANDSHAKE],
    [TLSProxy::Message::MT_CERTIFICATE,
        recipes::checkhandshake::RENEG_HANDSHAKE],
    [TLSProxy::Message::MT_SERVER_HELLO_DONE,
        recipes::checkhandshake::RENEG_HANDSHAKE],
    [TLSProxy::Message::MT_CLIENT_KEY_EXCHANGE,
        recipes::checkhandshake::RENEG_HANDSHAKE],
    [TLSProxy::Message::MT_FINISHED,
        recipes::checkhandshake::RENEG_HANDSHAKE],
    [TLSProxy::Message::MT_NEW_SESSION_TICKET,
        recipes::checkhandshake::RENEG_HANDSHAKE],
    [TLSProxy::Message::MT_FINISHED,
        recipes::checkhandshake::RENEG_HANDSHAKE],
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
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_RENEGOTIATE,
        recipes::checkhandshake::RENEGOTIATE_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_NPN,
        recipes::checkhandshake::NPN_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SRP,
        recipes::checkhandshake::SRP_CLI_EXTENSION],

    [TLSProxy::Message::MT_SERVER_HELLO, TLSProxy::Message::EXT_RENEGOTIATE,
        recipes::checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_SERVER_HELLO, TLSProxy::Message::EXT_ENCRYPT_THEN_MAC,
        recipes::checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_SERVER_HELLO, TLSProxy::Message::EXT_EXTENDED_MASTER_SECRET,
        recipes::checkhandshake::DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_SERVER_HELLO, TLSProxy::Message::EXT_SESSION_TICKET,
        recipes::checkhandshake::SESSION_TICKET_SRV_EXTENSION],
    [TLSProxy::Message::MT_SERVER_HELLO, TLSProxy::Message::EXT_SERVER_NAME,
        recipes::checkhandshake::SERVER_NAME_SRV_EXTENSION],
    [TLSProxy::Message::MT_SERVER_HELLO, TLSProxy::Message::EXT_STATUS_REQUEST,
        recipes::checkhandshake::STATUS_REQUEST_SRV_EXTENSION],
    [TLSProxy::Message::MT_SERVER_HELLO, TLSProxy::Message::EXT_ALPN,
        recipes::checkhandshake::ALPN_SRV_EXTENSION],
    [TLSProxy::Message::MT_SERVER_HELLO, TLSProxy::Message::EXT_SCT,
        recipes::checkhandshake::SCT_SRV_EXTENSION],
    [TLSProxy::Message::MT_SERVER_HELLO, TLSProxy::Message::EXT_NPN,
        recipes::checkhandshake::NPN_SRV_EXTENSION],
    [0,0,0]
);

#Test 1: Check we get all the right messages for a default handshake
(undef, my $session) = tempfile();
$proxy->serverconnects(2);
$proxy->clientflags("-no_tls1_3 -sess_out ".$session);
$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
plan tests => 20;
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
               recipes::checkhandshake::DEFAULT_EXTENSIONS,
               "Default handshake test");

#Test 2: Resumption handshake
$proxy->clearClient();
$proxy->clientflags("-no_tls1_3 -sess_in ".$session);
$proxy->clientstart();
checkhandshake($proxy, recipes::checkhandshake::RESUME_HANDSHAKE,
               recipes::checkhandshake::DEFAULT_EXTENSIONS
               & ~recipes::checkhandshake::SESSION_TICKET_SRV_EXTENSION,
               "Resumption handshake test");
unlink $session;

#Test 3: A status_request handshake (client request only)
$proxy->clear();
$proxy->clientflags("-no_tls1_3 -status");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
              recipes::checkhandshake::DEFAULT_EXTENSIONS
              | recipes::checkhandshake::STATUS_REQUEST_CLI_EXTENSION,
              "status_request handshake test (client)");

#Test 4: A status_request handshake (server support only)
$proxy->clear();
$proxy->clientflags("-no_tls1_3");
$proxy->serverflags("-status_file "
                    .srctop_file("test", "recipes", "ocsp-response.der"));
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
               recipes::checkhandshake::DEFAULT_EXTENSIONS,
              "status_request handshake test (server)");

#Test 5: A status_request handshake (client and server)
$proxy->clear();
$proxy->clientflags("-no_tls1_3 -status");
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
$proxy->clientflags("-no_tls1_3 -cert ".srctop_file("apps", "server.pem"));
$proxy->serverflags("-Verify 5");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::CLIENT_AUTH_HANDSHAKE,
               recipes::checkhandshake::DEFAULT_EXTENSIONS,
               "Client auth handshake test");

#Test 7: A handshake with a renegotiation
$proxy->clear();
$proxy->clientflags("-no_tls1_3");
$proxy->reneg(1);
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::RENEG_HANDSHAKE,
               recipes::checkhandshake::DEFAULT_EXTENSIONS,
               "Rengotiation handshake test");

#Test 8: Server name handshake (client request only)
$proxy->clear();
$proxy->clientflags("-no_tls1_3 -servername testhost");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
               recipes::checkhandshake::DEFAULT_EXTENSIONS
               | recipes::checkhandshake::SERVER_NAME_CLI_EXTENSION,
              "Server name handshake test (client)");

#Test 9: Server name handshake (server support only)
$proxy->clear();
$proxy->clientflags("-no_tls1_3");
$proxy->serverflags("-servername testhost");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
               recipes::checkhandshake::DEFAULT_EXTENSIONS,
              "Server name handshake test (server)");

#Test 10: Server name handshake (client and server)
$proxy->clear();
$proxy->clientflags("-no_tls1_3 -servername testhost");
$proxy->serverflags("-servername testhost");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
              recipes::checkhandshake::DEFAULT_EXTENSIONS
              | recipes::checkhandshake::SERVER_NAME_CLI_EXTENSION
              | recipes::checkhandshake::SERVER_NAME_SRV_EXTENSION,
              "Server name handshake test");

#Test 11: ALPN handshake (client request only)
$proxy->clear();
$proxy->clientflags("-no_tls1_3 -alpn test");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
               recipes::checkhandshake::DEFAULT_EXTENSIONS
               | recipes::checkhandshake::ALPN_CLI_EXTENSION,
              "ALPN handshake test (client)");

#Test 12: ALPN handshake (server support only)
$proxy->clear();
$proxy->clientflags("-no_tls1_3");
$proxy->serverflags("-alpn test");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
               recipes::checkhandshake::DEFAULT_EXTENSIONS,
              "ALPN handshake test (server)");

#Test 13: ALPN handshake (client and server)
$proxy->clear();
$proxy->clientflags("-no_tls1_3 -alpn test");
$proxy->serverflags("-alpn test");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
              recipes::checkhandshake::DEFAULT_EXTENSIONS
              | recipes::checkhandshake::ALPN_CLI_EXTENSION
              | recipes::checkhandshake::ALPN_SRV_EXTENSION,
              "ALPN handshake test");

#Test 14: SCT handshake (client request only)
$proxy->clear();
#Note: -ct also sends status_request
$proxy->clientflags("-no_tls1_3 -ct");
$proxy->serverflags("-status_file "
                    .srctop_file("test", "recipes", "ocsp-response.der"));
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::OCSP_HANDSHAKE,
              recipes::checkhandshake::DEFAULT_EXTENSIONS
              | recipes::checkhandshake::SCT_CLI_EXTENSION
              | recipes::checkhandshake::STATUS_REQUEST_CLI_EXTENSION
              | recipes::checkhandshake::STATUS_REQUEST_SRV_EXTENSION,
              "SCT handshake test (client)");

#Test 15: SCT handshake (server support only)
$proxy->clear();
#Note: -ct also sends status_request
$proxy->clientflags("-no_tls1_3");
$proxy->serverflags("-status_file "
                    .srctop_file("test", "recipes", "ocsp-response.der"));
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
              recipes::checkhandshake::DEFAULT_EXTENSIONS,
              "SCT handshake test (server)");

#Test 16: SCT handshake (client and server)
#There is no built-in server side support for this so we are actually also
#testing custom extensions here
$proxy->clear();
#Note: -ct also sends status_request
$proxy->clientflags("-no_tls1_3 -ct");
$proxy->serverflags("-status_file "
                    .srctop_file("test", "recipes", "ocsp-response.der")
                    ." -serverinfo ".srctop_file("test", "serverinfo.pem"));
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::OCSP_HANDSHAKE,
              recipes::checkhandshake::DEFAULT_EXTENSIONS
              | recipes::checkhandshake::SCT_CLI_EXTENSION
              | recipes::checkhandshake::SCT_SRV_EXTENSION
              | recipes::checkhandshake::STATUS_REQUEST_CLI_EXTENSION
              | recipes::checkhandshake::STATUS_REQUEST_SRV_EXTENSION,
              "SCT handshake test");


#Test 17: NPN handshake (client request only)
$proxy->clear();
$proxy->clientflags("-no_tls1_3 -nextprotoneg test");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
               recipes::checkhandshake::DEFAULT_EXTENSIONS
               | recipes::checkhandshake::NPN_CLI_EXTENSION,
              "NPN handshake test (client)");

#Test 18: NPN handshake (server support only)
$proxy->clear();
$proxy->clientflags("-no_tls1_3");
$proxy->serverflags("-nextprotoneg test");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
               recipes::checkhandshake::DEFAULT_EXTENSIONS,
              "NPN handshake test (server)");

#Test 19: NPN handshake (client and server)
$proxy->clear();
$proxy->clientflags("-no_tls1_3 -nextprotoneg test");
$proxy->serverflags("-nextprotoneg test");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::NPN_HANDSHAKE,
              recipes::checkhandshake::DEFAULT_EXTENSIONS
              | recipes::checkhandshake::NPN_CLI_EXTENSION
              | recipes::checkhandshake::NPN_SRV_EXTENSION,
              "NPN handshake test");

#Test 20: SRP extension
#Note: We are not actually going to perform an SRP handshake (TLSProxy does not
#support it). However it is sufficient for us to check that the SRP extension
#gets added on the client side. There is no SRP extension generated on the
#server side anyway.
$proxy->clear();
$proxy->clientflags("-no_tls1_3 -srpuser user -srppass pass:pass");
$proxy->start();
checkhandshake($proxy, recipes::checkhandshake::DEFAULT_HANDSHAKE,
              recipes::checkhandshake::DEFAULT_EXTENSIONS
              | recipes::checkhandshake::SRP_CLI_EXTENSION,
              "SRP extension test");
