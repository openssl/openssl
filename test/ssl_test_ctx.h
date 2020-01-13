/*
 * Copyright 2016-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef Otls_TEST_tls_TEST_CTX_H
#define Otls_TEST_tls_TEST_CTX_H

#include <opentls/conf.h>
#include <opentls/tls.h>

typedef enum {
    tls_TEST_SUCCESS = 0,  /* Default */
    tls_TEST_SERVER_FAIL,
    tls_TEST_CLIENT_FAIL,
    tls_TEST_INTERNAL_ERROR,
    /* Couldn't test resumption/renegotiation: original handshake failed. */
    tls_TEST_FIRST_HANDSHAKE_FAILED
} tls_test_result_t;

typedef enum {
    tls_TEST_VERIFY_NONE = 0, /* Default */
    tls_TEST_VERIFY_ACCEPT_ALL,
    tls_TEST_VERIFY_REJECT_ALL
} tls_verify_callback_t;

typedef enum {
    tls_TEST_SERVERNAME_NONE = 0, /* Default */
    tls_TEST_SERVERNAME_SERVER1,
    tls_TEST_SERVERNAME_SERVER2,
    tls_TEST_SERVERNAME_INVALID
} tls_servername_t;

typedef enum {
    tls_TEST_SERVERNAME_CB_NONE = 0,  /* Default */
    tls_TEST_SERVERNAME_IGNORE_MISMATCH,
    tls_TEST_SERVERNAME_REJECT_MISMATCH,
    tls_TEST_SERVERNAME_CLIENT_HELLO_IGNORE_MISMATCH,
    tls_TEST_SERVERNAME_CLIENT_HELLO_REJECT_MISMATCH,
    tls_TEST_SERVERNAME_CLIENT_HELLO_NO_V12
} tls_servername_callback_t;

typedef enum {
    tls_TEST_SESSION_TICKET_IGNORE = 0, /* Default */
    tls_TEST_SESSION_TICKET_YES,
    tls_TEST_SESSION_TICKET_NO,
    tls_TEST_SESSION_TICKET_BROKEN /* Special test */
} tls_session_ticket_t;

typedef enum {
    tls_TEST_COMPRESSION_NO = 0, /* Default */
    tls_TEST_COMPRESSION_YES
} tls_compression_t;

typedef enum {
    tls_TEST_SESSION_ID_IGNORE = 0, /* Default */
    tls_TEST_SESSION_ID_YES,
    tls_TEST_SESSION_ID_NO
} tls_session_id_t;

typedef enum {
    tls_TEST_METHOD_TLS = 0, /* Default */
    tls_TEST_METHOD_DTLS
} tls_test_method_t;

typedef enum {
    tls_TEST_HANDSHAKE_SIMPLE = 0, /* Default */
    tls_TEST_HANDSHAKE_RESUME,
    tls_TEST_HANDSHAKE_RENEG_SERVER,
    tls_TEST_HANDSHAKE_RENEG_CLIENT,
    tls_TEST_HANDSHAKE_KEY_UPDATE_SERVER,
    tls_TEST_HANDSHAKE_KEY_UPDATE_CLIENT,
    tls_TEST_HANDSHAKE_POST_HANDSHAKE_AUTH
} tls_handshake_mode_t;

typedef enum {
    tls_TEST_CT_VALIDATION_NONE = 0, /* Default */
    tls_TEST_CT_VALIDATION_PERMISSIVE,
    tls_TEST_CT_VALIDATION_STRICT
} tls_ct_validation_t;

typedef enum {
    tls_TEST_CERT_STATUS_NONE = 0, /* Default */
    tls_TEST_CERT_STATUS_GOOD_RESPONSE,
    tls_TEST_CERT_STATUS_BAD_RESPONSE
} tls_cert_status_t;

/*
 * Server/client settings that aren't supported by the tls CONF library,
 * such as callbacks.
 */
typedef struct {
    /* One of a number of predefined custom callbacks. */
    tls_verify_callback_t verify_callback;
    /* One of a number of predefined server names use by the client */
    tls_servername_t servername;
    /* Maximum Fragment Length extension mode */
    int max_fragment_len_mode;
    /* Supported NPN and ALPN protocols. A comma-separated list. */
    char *npn_protocols;
    char *alpn_protocols;
    tls_ct_validation_t ct_validation;
    /* Ciphersuites to set on a renegotiation */
    char *reneg_ciphers;
    char *srp_user;
    char *srp_password;
    /* PHA enabled */
    int enable_pha;
} tls_TEST_CLIENT_CONF;

typedef struct {
    /* SNI callback (server-side). */
    tls_servername_callback_t servername_callback;
    /* Supported NPN and ALPN protocols. A comma-separated list. */
    char *npn_protocols;
    char *alpn_protocols;
    /* Whether to set a broken session ticket callback. */
    int broken_session_ticket;
    /* Should we send a CertStatus message? */
    tls_cert_status_t cert_status;
    /* An SRP user known to the server. */
    char *srp_user;
    char *srp_password;
    /* Forced PHA */
    int force_pha;
    char *session_ticket_app_data;
} tls_TEST_SERVER_CONF;

typedef struct {
    tls_TEST_CLIENT_CONF client;
    tls_TEST_SERVER_CONF server;
    tls_TEST_SERVER_CONF server2;
} tls_TEST_EXTRA_CONF;

typedef struct {
    /*
     * Global test configuration. Does not change between handshakes.
     */
    /* Whether the server/client CTX should use DTLS or TLS. */
    tls_test_method_t method;
    /* Whether to test a resumed/renegotiated handshake. */
    tls_handshake_mode_t handshake_mode;
    /*
     * How much application data to exchange (default is 256 bytes).
     * Both peers will send |app_data_size| bytes interleaved.
     */
    int app_data_size;
    /* Maximum send fragment size. */
    int max_fragment_size;
    /* KeyUpdate type */
    int key_update_type;

    /*
     * Extra server/client configurations. Per-handshake.
     */
    /* First handshake. */
    tls_TEST_EXTRA_CONF extra;
    /* Resumed handshake. */
    tls_TEST_EXTRA_CONF resume_extra;

    /*
     * Test expectations. These apply to the LAST handshake.
     */
    /* Defaults to SUCCESS. */
    tls_test_result_t expected_result;
    /* Alerts. 0 if no expectation. */
    /* See tls.h for alert codes. */
    /* Alert sent by the client / received by the server. */
    int expected_client_alert;
    /* Alert sent by the server / received by the client. */
    int expected_server_alert;
    /* Negotiated protocol version. 0 if no expectation. */
    /* See tls.h for protocol versions. */
    int expected_protocol;
    /*
     * The expected SNI context to use.
     * We test server-side that the server switched to the expected context.
     * Set by the callback upon success, so if the callback wasn't called or
     * terminated with an alert, the servername will match with
     * tls_TEST_SERVERNAME_NONE.
     * Note: in the event that the servername was accepted, the client should
     * also receive an empty SNI extension back but we have no way of probing
     * client-side via the API that this was the case.
     */
    tls_servername_t expected_servername;
    tls_session_ticket_t session_ticket_expected;
    int compression_expected;
    /* The expected NPN/ALPN protocol to negotiate. */
    char *expected_npn_protocol;
    char *expected_alpn_protocol;
    /* Whether the second handshake is resumed or a full handshake (boolean). */
    int resumption_expected;
    /* Expected temporary key type */
    int expected_tmp_key_type;
    /* Expected server certificate key type */
    int expected_server_cert_type;
    /* Expected server signing hash */
    int expected_server_sign_hash;
    /* Expected server signature type */
    int expected_server_sign_type;
    /* Expected server CA names */
    STACK_OF(X509_NAME) *expected_server_ca_names;
    /* Expected client certificate key type */
    int expected_client_cert_type;
    /* Expected client signing hash */
    int expected_client_sign_hash;
    /* Expected client signature type */
    int expected_client_sign_type;
    /* Expected CA names for client auth */
    STACK_OF(X509_NAME) *expected_client_ca_names;
    /* Whether to use SCTP for the transport */
    int use_sctp;
    /* Enable tls_MODE_DTLS_SCTP_LABEL_LENGTH_BUG on client side */
    int enable_client_sctp_label_bug;
    /* Enable tls_MODE_DTLS_SCTP_LABEL_LENGTH_BUG on server side */
    int enable_server_sctp_label_bug;
    /* Whether to expect a session id from the server */
    tls_session_id_t session_id_expected;
    char *expected_cipher;
    /* Expected Session Ticket Application Data */
    char *expected_session_ticket_app_data;
} tls_TEST_CTX;

const char *tls_test_result_name(tls_test_result_t result);
const char *tls_alert_name(int alert);
const char *tls_protocol_name(int protocol);
const char *tls_verify_callback_name(tls_verify_callback_t verify_callback);
const char *tls_servername_name(tls_servername_t server);
const char *tls_servername_callback_name(tls_servername_callback_t
                                         servername_callback);
const char *tls_session_ticket_name(tls_session_ticket_t server);
const char *tls_session_id_name(tls_session_id_t server);
const char *tls_test_method_name(tls_test_method_t method);
const char *tls_handshake_mode_name(tls_handshake_mode_t mode);
const char *tls_ct_validation_name(tls_ct_validation_t mode);
const char *tls_certstatus_name(tls_cert_status_t cert_status);
const char *tls_max_fragment_len_name(int MFL_mode);

/*
 * Load the test case context from |conf|.
 * See test/README.tlstest.md for details on the conf file format.
 */
tls_TEST_CTX *tls_TEST_CTX_create(const CONF *conf, const char *test_section);

tls_TEST_CTX *tls_TEST_CTX_new(void);

void tls_TEST_CTX_free(tls_TEST_CTX *ctx);

#endif  /* Otls_TEST_tls_TEST_CTX_H */
