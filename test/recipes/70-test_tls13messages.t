#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use File::Temp qw(tempfile);
use TLSProxy::Proxy;
my $test_name = "test_tls13messages";
setup($test_name);

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

use constant {
    DEFAULT_HANDSHAKE => 1,
    OCSP_HANDSHAKE => 2,
    RESUME_HANDSHAKE => 4,
    CLIENT_AUTH_HANDSHAKE => 8,
    ALL_HANDSHAKES => 15
};

use constant {
    DEFAULT_EXTENSIONS => 0x00000001,
    SERVER_NAME_CLI_EXTENSION => 0x00000002,
    SERVER_NAME_SRV_EXTENSION => 0x00000004,
    STATUS_REQUEST_CLI_EXTENSION => 0x00000008,
    STATUS_REQUEST_SRV_EXTENSION => 0x00000010,
    ALPN_CLI_EXTENSION => 0x00000020,
    ALPN_SRV_EXTENSION => 0x00000040,
    SCT_CLI_EXTENSION => 0x00000080
};

my @handmessages = (
    [TLSProxy::Message::MT_CLIENT_HELLO, ALL_HANDSHAKES],
    [TLSProxy::Message::MT_SERVER_HELLO, ALL_HANDSHAKES],
    [TLSProxy::Message::MT_ENCRYPTED_EXTENSIONS, ALL_HANDSHAKES],
    [TLSProxy::Message::MT_CERTIFICATE_REQUEST, CLIENT_AUTH_HANDSHAKE],
    [TLSProxy::Message::MT_CERTIFICATE, ALL_HANDSHAKES & ~RESUME_HANDSHAKE],
    [TLSProxy::Message::MT_CERTIFICATE_STATUS, OCSP_HANDSHAKE],
    [TLSProxy::Message::MT_FINISHED, ALL_HANDSHAKES],
    [TLSProxy::Message::MT_CERTIFICATE, CLIENT_AUTH_HANDSHAKE],
    [TLSProxy::Message::MT_CERTIFICATE_VERIFY, CLIENT_AUTH_HANDSHAKE],
    [TLSProxy::Message::MT_FINISHED, ALL_HANDSHAKES],
    [0, 0]
);

my @extensions = (
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SERVER_NAME, SERVER_NAME_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_STATUS_REQUEST, STATUS_REQUEST_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SUPPORTED_GROUPS, DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_EC_POINT_FORMATS, DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SIG_ALGS, DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_ALPN, ALPN_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SCT, SCT_CLI_EXTENSION],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_ENCRYPT_THEN_MAC, DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_EXTENDED_MASTER_SECRET, DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SESSION_TICKET, DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_KEY_SHARE, DEFAULT_EXTENSIONS],
    [TLSProxy::Message::MT_CLIENT_HELLO, TLSProxy::Message::EXT_SUPPORTED_VERSIONS, DEFAULT_EXTENSIONS],

    [TLSProxy::Message::MT_SERVER_HELLO, TLSProxy::Message::EXT_KEY_SHARE, DEFAULT_EXTENSIONS],

    [TLSProxy::Message::MT_ENCRYPTED_EXTENSIONS, TLSProxy::Message::EXT_SERVER_NAME, SERVER_NAME_SRV_EXTENSION],
    [TLSProxy::Message::MT_ENCRYPTED_EXTENSIONS, TLSProxy::Message::EXT_STATUS_REQUEST, STATUS_REQUEST_SRV_EXTENSION],
    [TLSProxy::Message::MT_ENCRYPTED_EXTENSIONS, TLSProxy::Message::EXT_ALPN, ALPN_SRV_EXTENSION],
    [0,0,0]
);

my $proxy = TLSProxy::Proxy->new(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

sub checkmessages($$$);

#Test 1: Check we get all the right messages for a default handshake
(undef, my $session) = tempfile();
#$proxy->serverconnects(2);
$proxy->clientflags("-sess_out ".$session);
$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
plan tests => 12;
checkmessages(DEFAULT_HANDSHAKE, DEFAULT_EXTENSIONS, "Default handshake test");

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
checkmessages(DEFAULT_HANDSHAKE,
              DEFAULT_EXTENSIONS | STATUS_REQUEST_CLI_EXTENSION,
              "status_request handshake test (client)");

#Test 4: A status_request handshake (server support only)
$proxy->clear();
$proxy->serverflags("-status_file "
                    .srctop_file("test", "recipes", "ocsp-response.der"));
$proxy->start();
checkmessages(DEFAULT_HANDSHAKE, DEFAULT_EXTENSIONS,
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
checkmessages(OCSP_HANDSHAKE,
              DEFAULT_EXTENSIONS | STATUS_REQUEST_CLI_EXTENSION
              | STATUS_REQUEST_SRV_EXTENSION,
              "status_request handshake test");

#Test 6: A client auth handshake
$proxy->clear();
$proxy->clientflags("-cert ".srctop_file("apps", "server.pem"));
$proxy->serverflags("-Verify 5");
$proxy->start();
checkmessages(CLIENT_AUTH_HANDSHAKE, DEFAULT_EXTENSIONS,
              "Client auth handshake test");

#Test 7: Server name handshake (client request only)
$proxy->clear();
$proxy->clientflags("-servername testhost");
$proxy->start();
checkmessages(DEFAULT_HANDSHAKE, DEFAULT_EXTENSIONS | SERVER_NAME_CLI_EXTENSION,
              "Server name handshake test (client)");

#Test 8: Server name handshake (server support only)
$proxy->clear();
$proxy->serverflags("-servername testhost");
$proxy->start();
checkmessages(DEFAULT_HANDSHAKE, DEFAULT_EXTENSIONS,
              "Server name handshake test (server)");

#Test 9: Server name handshake (client and server)
$proxy->clear();
$proxy->clientflags("-servername testhost");
$proxy->serverflags("-servername testhost");
$proxy->start();
checkmessages(DEFAULT_HANDSHAKE,
              DEFAULT_EXTENSIONS | SERVER_NAME_CLI_EXTENSION
              | SERVER_NAME_SRV_EXTENSION,
              "Server name handshake test");

#Test 10: ALPN handshake (client request only)
$proxy->clear();
$proxy->clientflags("-alpn test");
$proxy->start();
checkmessages(DEFAULT_HANDSHAKE, DEFAULT_EXTENSIONS | ALPN_CLI_EXTENSION,
              "ALPN handshake test (client)");

#Test 11: ALPN handshake (server support only)
$proxy->clear();
$proxy->serverflags("-alpn test");
$proxy->start();
checkmessages(DEFAULT_HANDSHAKE, DEFAULT_EXTENSIONS,
              "ALPN handshake test (server)");
              
#Test 12: ALPN handshake (client and server)
$proxy->clear();
$proxy->clientflags("-alpn test");
$proxy->serverflags("-alpn test");
$proxy->start();
checkmessages(DEFAULT_HANDSHAKE,
              DEFAULT_EXTENSIONS | ALPN_CLI_EXTENSION | ALPN_SRV_EXTENSION,
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
checkmessages(OCSP_HANDSHAKE,
              DEFAULT_EXTENSIONS | SCT_CLI_EXTENSION
              | STATUS_REQUEST_CLI_EXTENSION | STATUS_REQUEST_SRV_EXTENSION,
              "SCT handshake test");

sub checkmessages($$$)
{
    my ($handtype, $exttype, $testname) = @_;

    subtest $testname => sub {
        my $loop = 0;
        my $numtests;
        my $extcount;

        #First count the number of tests
        for ($numtests = 1; $handmessages[$loop][1] != 0; $loop++) {
            $numtests++ if (($handmessages[$loop][1] & $handtype) != 0);
        }

        #Add number of extensions we check plus 3 for the number of messages
        #that contain extensions
        $numtests += $#extensions + 3;

        plan tests => $numtests;

        $loop = 0;
        foreach my $message (@{$proxy->message_list}) {
            for (; $handmessages[$loop][1] != 0
                   && ($handmessages[$loop][1] & $handtype) == 0; $loop++) {
                next;
            }
            ok($handmessages[$loop][1] != 0
               && $message->mt == $handmessages[$loop][0],
               "Message type check. Got ".$message->mt
               .", expected ".$handmessages[$loop][0]);
            $loop++;


            next if ($message->mt() != TLSProxy::Message::MT_CLIENT_HELLO
                    && $message->mt() != TLSProxy::Message::MT_SERVER_HELLO
                    && $message->mt() !=
                       TLSProxy::Message::MT_ENCRYPTED_EXTENSIONS);
             #Now check that we saw the extensions we expected
             my $msgexts = $message->extension_data();
             for (my $extloop = 0, $extcount = 0; $extensions[$extloop][2] != 0;
                                $extloop++) {
                next if ($message->mt() != $extensions[$extloop][0]);
                ok (($extensions[$extloop][2] & $exttype) == 0
                      || defined ($msgexts->{$extensions[$extloop][1]}),
                    "Extension presence check (Message: ".$message->mt()
                    ." Extension: ".($extensions[$extloop][2] & $exttype).", "
                    .$extloop.")");
                $extcount++ if (($extensions[$extloop][2] & $exttype) != 0);
             }
            ok($extcount == keys %$msgexts, "Extensions count mismatch ("
                                            .$extcount.", ".(keys %$msgexts)
                                            .")");
        }
        ok($handmessages[$loop][1] == 0, "All expected messages processed");
    }
}
