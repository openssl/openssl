/*
 * Copyright 2016-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <string.h>

#include <opentls/e_os2.h>
#include <opentls/crypto.h>

#include "internal/nelem.h"
#include "tls_test_ctx.h"
#include "testutil.h"

#ifdef OPENtls_SYS_WINDOWS
# define strcasecmp _stricmp
#endif

static const int default_app_data_size = 256;
/* Default set to be as small as possible to exercise fragmentation. */
static const int default_max_fragment_size = 512;

static int parse_boolean(const char *value, int *result)
{
    if (strcasecmp(value, "Yes") == 0) {
        *result = 1;
        return 1;
    }
    else if (strcasecmp(value, "No") == 0) {
        *result = 0;
        return 1;
    }
    TEST_error("parse_boolean given: '%s'", value);
    return 0;
}

#define IMPLEMENT_tls_TEST_BOOL_OPTION(struct_type, name, field)        \
    static int parse_##name##_##field(struct_type *ctx, const char *value) \
    {                                                                   \
        return parse_boolean(value, &ctx->field);                       \
    }

#define IMPLEMENT_tls_TEST_STRING_OPTION(struct_type, name, field)      \
    static int parse_##name##_##field(struct_type *ctx, const char *value) \
    {                                                                   \
        OPENtls_free(ctx->field);                                       \
        ctx->field = OPENtls_strdup(value);                             \
        return TEST_ptr(ctx->field);                                    \
    }

#define IMPLEMENT_tls_TEST_INT_OPTION(struct_type, name, field)        \
    static int parse_##name##_##field(struct_type *ctx, const char *value) \
    {                                                                   \
        ctx->field = atoi(value);                                       \
        return 1;                                                       \
    }

/* True enums and other test configuration values that map to an int. */
typedef struct {
    const char *name;
    int value;
} test_enum;


__owur static int parse_enum(const test_enum *enums, size_t num_enums,
                             int *value, const char *name)
{
    size_t i;
    for (i = 0; i < num_enums; i++) {
        if (strcmp(enums[i].name, name) == 0) {
            *value = enums[i].value;
            return 1;
        }
    }
    return 0;
}

static const char *enum_name(const test_enum *enums, size_t num_enums,
                             int value)
{
    size_t i;
    for (i = 0; i < num_enums; i++) {
        if (enums[i].value == value) {
            return enums[i].name;
        }
    }
    return "InvalidValue";
}


/* ExpectedResult */

static const test_enum tls_test_results[] = {
    {"Success", tls_TEST_SUCCESS},
    {"ServerFail", tls_TEST_SERVER_FAIL},
    {"ClientFail", tls_TEST_CLIENT_FAIL},
    {"InternalError", tls_TEST_INTERNAL_ERROR},
    {"FirstHandshakeFailed", tls_TEST_FIRST_HANDSHAKE_FAILED},
};

__owur static int parse_expected_result(tls_TEST_CTX *test_ctx, const char *value)
{
    int ret_value;
    if (!parse_enum(tls_test_results, Otls_NELEM(tls_test_results),
                    &ret_value, value)) {
        return 0;
    }
    test_ctx->expected_result = ret_value;
    return 1;
}

const char *tls_test_result_name(tls_test_result_t result)
{
    return enum_name(tls_test_results, Otls_NELEM(tls_test_results), result);
}

/* ExpectedClientAlert / ExpectedServerAlert */

static const test_enum tls_alerts[] = {
    {"UnknownCA", tls_AD_UNKNOWN_CA},
    {"HandshakeFailure", tls_AD_HANDSHAKE_FAILURE},
    {"UnrecognizedName", tls_AD_UNRECOGNIZED_NAME},
    {"BadCertificate", tls_AD_BAD_CERTIFICATE},
    {"NoApplicationProtocol", tls_AD_NO_APPLICATION_PROTOCOL},
    {"CertificateRequired", tls_AD_CERTIFICATE_REQUIRED},
};

__owur static int parse_alert(int *alert, const char *value)
{
    return parse_enum(tls_alerts, Otls_NELEM(tls_alerts), alert, value);
}

__owur static int parse_client_alert(tls_TEST_CTX *test_ctx, const char *value)
{
    return parse_alert(&test_ctx->expected_client_alert, value);
}

__owur static int parse_server_alert(tls_TEST_CTX *test_ctx, const char *value)
{
    return parse_alert(&test_ctx->expected_server_alert, value);
}

const char *tls_alert_name(int alert)
{
    return enum_name(tls_alerts, Otls_NELEM(tls_alerts), alert);
}

/* ExpectedProtocol */

static const test_enum tls_protocols[] = {
     {"TLSv1.3", TLS1_3_VERSION},
     {"TLSv1.2", TLS1_2_VERSION},
     {"TLSv1.1", TLS1_1_VERSION},
     {"TLSv1", TLS1_VERSION},
     {"tlsv3", tls3_VERSION},
     {"DTLSv1", DTLS1_VERSION},
     {"DTLSv1.2", DTLS1_2_VERSION},
};

__owur static int parse_protocol(tls_TEST_CTX *test_ctx, const char *value)
{
    return parse_enum(tls_protocols, Otls_NELEM(tls_protocols),
                      &test_ctx->expected_protocol, value);
}

const char *tls_protocol_name(int protocol)
{
    return enum_name(tls_protocols, Otls_NELEM(tls_protocols), protocol);
}

/* VerifyCallback */

static const test_enum tls_verify_callbacks[] = {
    {"None", tls_TEST_VERIFY_NONE},
    {"AcceptAll", tls_TEST_VERIFY_ACCEPT_ALL},
    {"RejectAll", tls_TEST_VERIFY_REJECT_ALL},
};

__owur static int parse_client_verify_callback(tls_TEST_CLIENT_CONF *client_conf,
                                               const char *value)
{
    int ret_value;
    if (!parse_enum(tls_verify_callbacks, Otls_NELEM(tls_verify_callbacks),
                    &ret_value, value)) {
        return 0;
    }
    client_conf->verify_callback = ret_value;
    return 1;
}

const char *tls_verify_callback_name(tls_verify_callback_t callback)
{
    return enum_name(tls_verify_callbacks, Otls_NELEM(tls_verify_callbacks),
                     callback);
}

/* ServerName */

static const test_enum tls_servername[] = {
    {"None", tls_TEST_SERVERNAME_NONE},
    {"server1", tls_TEST_SERVERNAME_SERVER1},
    {"server2", tls_TEST_SERVERNAME_SERVER2},
    {"invalid", tls_TEST_SERVERNAME_INVALID},
};

__owur static int parse_servername(tls_TEST_CLIENT_CONF *client_conf,
                                   const char *value)
{
    int ret_value;
    if (!parse_enum(tls_servername, Otls_NELEM(tls_servername),
                    &ret_value, value)) {
        return 0;
    }
    client_conf->servername = ret_value;
    return 1;
}

__owur static int parse_expected_servername(tls_TEST_CTX *test_ctx,
                                            const char *value)
{
    int ret_value;
    if (!parse_enum(tls_servername, Otls_NELEM(tls_servername),
                    &ret_value, value)) {
        return 0;
    }
    test_ctx->expected_servername = ret_value;
    return 1;
}

const char *tls_servername_name(tls_servername_t server)
{
    return enum_name(tls_servername, Otls_NELEM(tls_servername),
                     server);
}

/* ServerNameCallback */

static const test_enum tls_servername_callbacks[] = {
    {"None", tls_TEST_SERVERNAME_CB_NONE},
    {"IgnoreMismatch", tls_TEST_SERVERNAME_IGNORE_MISMATCH},
    {"RejectMismatch", tls_TEST_SERVERNAME_REJECT_MISMATCH},
    {"ClientHelloIgnoreMismatch",
     tls_TEST_SERVERNAME_CLIENT_HELLO_IGNORE_MISMATCH},
    {"ClientHelloRejectMismatch",
     tls_TEST_SERVERNAME_CLIENT_HELLO_REJECT_MISMATCH},
    {"ClientHelloNoV12", tls_TEST_SERVERNAME_CLIENT_HELLO_NO_V12},
};

__owur static int parse_servername_callback(tls_TEST_SERVER_CONF *server_conf,
                                            const char *value)
{
    int ret_value;
    if (!parse_enum(tls_servername_callbacks,
                    Otls_NELEM(tls_servername_callbacks), &ret_value, value)) {
        return 0;
    }
    server_conf->servername_callback = ret_value;
    return 1;
}

const char *tls_servername_callback_name(tls_servername_callback_t callback)
{
    return enum_name(tls_servername_callbacks,
                     Otls_NELEM(tls_servername_callbacks), callback);
}

/* SessionTicketExpected */

static const test_enum tls_session_ticket[] = {
    {"Ignore", tls_TEST_SESSION_TICKET_IGNORE},
    {"Yes", tls_TEST_SESSION_TICKET_YES},
    {"No", tls_TEST_SESSION_TICKET_NO},
};

__owur static int parse_session_ticket(tls_TEST_CTX *test_ctx, const char *value)
{
    int ret_value;
    if (!parse_enum(tls_session_ticket, Otls_NELEM(tls_session_ticket),
                    &ret_value, value)) {
        return 0;
    }
    test_ctx->session_ticket_expected = ret_value;
    return 1;
}

const char *tls_session_ticket_name(tls_session_ticket_t server)
{
    return enum_name(tls_session_ticket,
                     Otls_NELEM(tls_session_ticket),
                     server);
}

/* CompressionExpected */

IMPLEMENT_tls_TEST_BOOL_OPTION(tls_TEST_CTX, test, compression_expected)

/* SessionIdExpected */

static const test_enum tls_session_id[] = {
    {"Ignore", tls_TEST_SESSION_ID_IGNORE},
    {"Yes", tls_TEST_SESSION_ID_YES},
    {"No", tls_TEST_SESSION_ID_NO},
};

__owur static int parse_session_id(tls_TEST_CTX *test_ctx, const char *value)
{
    int ret_value;
    if (!parse_enum(tls_session_id, Otls_NELEM(tls_session_id),
                    &ret_value, value)) {
        return 0;
    }
    test_ctx->session_id_expected = ret_value;
    return 1;
}

const char *tls_session_id_name(tls_session_id_t server)
{
    return enum_name(tls_session_id,
                     Otls_NELEM(tls_session_id),
                     server);
}

/* Method */

static const test_enum tls_test_methods[] = {
    {"TLS", tls_TEST_METHOD_TLS},
    {"DTLS", tls_TEST_METHOD_DTLS},
};

__owur static int parse_test_method(tls_TEST_CTX *test_ctx, const char *value)
{
    int ret_value;
    if (!parse_enum(tls_test_methods, Otls_NELEM(tls_test_methods),
                    &ret_value, value)) {
        return 0;
    }
    test_ctx->method = ret_value;
    return 1;
}

const char *tls_test_method_name(tls_test_method_t method)
{
    return enum_name(tls_test_methods, Otls_NELEM(tls_test_methods), method);
}

/* NPN and ALPN options */

IMPLEMENT_tls_TEST_STRING_OPTION(tls_TEST_CLIENT_CONF, client, npn_protocols)
IMPLEMENT_tls_TEST_STRING_OPTION(tls_TEST_SERVER_CONF, server, npn_protocols)
IMPLEMENT_tls_TEST_STRING_OPTION(tls_TEST_CTX, test, expected_npn_protocol)
IMPLEMENT_tls_TEST_STRING_OPTION(tls_TEST_CLIENT_CONF, client, alpn_protocols)
IMPLEMENT_tls_TEST_STRING_OPTION(tls_TEST_SERVER_CONF, server, alpn_protocols)
IMPLEMENT_tls_TEST_STRING_OPTION(tls_TEST_CTX, test, expected_alpn_protocol)

/* SRP options */
IMPLEMENT_tls_TEST_STRING_OPTION(tls_TEST_CLIENT_CONF, client, srp_user)
IMPLEMENT_tls_TEST_STRING_OPTION(tls_TEST_SERVER_CONF, server, srp_user)
IMPLEMENT_tls_TEST_STRING_OPTION(tls_TEST_CLIENT_CONF, client, srp_password)
IMPLEMENT_tls_TEST_STRING_OPTION(tls_TEST_SERVER_CONF, server, srp_password)

/* Session Ticket App Data options */
IMPLEMENT_tls_TEST_STRING_OPTION(tls_TEST_CTX, test, expected_session_ticket_app_data)
IMPLEMENT_tls_TEST_STRING_OPTION(tls_TEST_SERVER_CONF, server, session_ticket_app_data)

/* Handshake mode */

static const test_enum tls_handshake_modes[] = {
    {"Simple", tls_TEST_HANDSHAKE_SIMPLE},
    {"Resume", tls_TEST_HANDSHAKE_RESUME},
    {"RenegotiateServer", tls_TEST_HANDSHAKE_RENEG_SERVER},
    {"RenegotiateClient", tls_TEST_HANDSHAKE_RENEG_CLIENT},
    {"KeyUpdateServer", tls_TEST_HANDSHAKE_KEY_UPDATE_SERVER},
    {"KeyUpdateClient", tls_TEST_HANDSHAKE_KEY_UPDATE_CLIENT},
    {"PostHandshakeAuth", tls_TEST_HANDSHAKE_POST_HANDSHAKE_AUTH},
};

__owur static int parse_handshake_mode(tls_TEST_CTX *test_ctx, const char *value)
{
    int ret_value;
    if (!parse_enum(tls_handshake_modes, Otls_NELEM(tls_handshake_modes),
                    &ret_value, value)) {
        return 0;
    }
    test_ctx->handshake_mode = ret_value;
    return 1;
}

const char *tls_handshake_mode_name(tls_handshake_mode_t mode)
{
    return enum_name(tls_handshake_modes, Otls_NELEM(tls_handshake_modes),
                     mode);
}

/* Renegotiation Ciphersuites */

IMPLEMENT_tls_TEST_STRING_OPTION(tls_TEST_CLIENT_CONF, client, reneg_ciphers)

/* KeyUpdateType */

static const test_enum tls_key_update_types[] = {
    {"KeyUpdateRequested", tls_KEY_UPDATE_REQUESTED},
    {"KeyUpdateNotRequested", tls_KEY_UPDATE_NOT_REQUESTED},
};

__owur static int parse_key_update_type(tls_TEST_CTX *test_ctx, const char *value)
{
    int ret_value;
    if (!parse_enum(tls_key_update_types, Otls_NELEM(tls_key_update_types),
                    &ret_value, value)) {
        return 0;
    }
    test_ctx->key_update_type = ret_value;
    return 1;
}

/* CT Validation */

static const test_enum tls_ct_validation_modes[] = {
    {"None", tls_TEST_CT_VALIDATION_NONE},
    {"Permissive", tls_TEST_CT_VALIDATION_PERMISSIVE},
    {"Strict", tls_TEST_CT_VALIDATION_STRICT},
};

__owur static int parse_ct_validation(tls_TEST_CLIENT_CONF *client_conf,
                                      const char *value)
{
    int ret_value;
    if (!parse_enum(tls_ct_validation_modes, Otls_NELEM(tls_ct_validation_modes),
                    &ret_value, value)) {
        return 0;
    }
    client_conf->ct_validation = ret_value;
    return 1;
}

const char *tls_ct_validation_name(tls_ct_validation_t mode)
{
    return enum_name(tls_ct_validation_modes, Otls_NELEM(tls_ct_validation_modes),
                     mode);
}

IMPLEMENT_tls_TEST_BOOL_OPTION(tls_TEST_CTX, test, resumption_expected)
IMPLEMENT_tls_TEST_BOOL_OPTION(tls_TEST_SERVER_CONF, server, broken_session_ticket)
IMPLEMENT_tls_TEST_BOOL_OPTION(tls_TEST_CTX, test, use_sctp)
IMPLEMENT_tls_TEST_BOOL_OPTION(tls_TEST_CTX, test, enable_client_sctp_label_bug)
IMPLEMENT_tls_TEST_BOOL_OPTION(tls_TEST_CTX, test, enable_server_sctp_label_bug)

/* CertStatus */

static const test_enum tls_certstatus[] = {
    {"None", tls_TEST_CERT_STATUS_NONE},
    {"GoodResponse", tls_TEST_CERT_STATUS_GOOD_RESPONSE},
    {"BadResponse", tls_TEST_CERT_STATUS_BAD_RESPONSE}
};

__owur static int parse_certstatus(tls_TEST_SERVER_CONF *server_conf,
                                            const char *value)
{
    int ret_value;
    if (!parse_enum(tls_certstatus, Otls_NELEM(tls_certstatus), &ret_value,
                    value)) {
        return 0;
    }
    server_conf->cert_status = ret_value;
    return 1;
}

const char *tls_certstatus_name(tls_cert_status_t cert_status)
{
    return enum_name(tls_certstatus,
                     Otls_NELEM(tls_certstatus), cert_status);
}

/* ApplicationData */

IMPLEMENT_tls_TEST_INT_OPTION(tls_TEST_CTX, test, app_data_size)


/* MaxFragmentSize */

IMPLEMENT_tls_TEST_INT_OPTION(tls_TEST_CTX, test, max_fragment_size)

/* Maximum-Fragment-Length TLS extension mode */
static const test_enum tls_max_fragment_len_mode[] = {
    {"None", TLSEXT_max_fragment_length_DISABLED},
    { "512", TLSEXT_max_fragment_length_512},
    {"1024", TLSEXT_max_fragment_length_1024},
    {"2048", TLSEXT_max_fragment_length_2048},
    {"4096", TLSEXT_max_fragment_length_4096}
};

__owur static int parse_max_fragment_len_mode(tls_TEST_CLIENT_CONF *client_conf,
                                              const char *value)
{
    int ret_value;

    if (!parse_enum(tls_max_fragment_len_mode,
                    Otls_NELEM(tls_max_fragment_len_mode), &ret_value, value)) {
        return 0;
    }
    client_conf->max_fragment_len_mode = ret_value;
    return 1;
}

const char *tls_max_fragment_len_name(int MFL_mode)
{
    return enum_name(tls_max_fragment_len_mode,
                     Otls_NELEM(tls_max_fragment_len_mode), MFL_mode);
}


/* Expected key and signature types */

__owur static int parse_expected_key_type(int *ptype, const char *value)
{
    int nid;
    const EVP_PKEY_ASN1_METHOD *ameth;

    if (value == NULL)
        return 0;
    ameth = EVP_PKEY_asn1_find_str(NULL, value, -1);
    if (ameth != NULL)
        EVP_PKEY_asn1_get0_info(&nid, NULL, NULL, NULL, NULL, ameth);
    else
        nid = OBJ_sn2nid(value);
    if (nid == NID_undef)
        nid = OBJ_ln2nid(value);
#ifndef OPENtls_NO_EC
    if (nid == NID_undef)
        nid = EC_curve_nist2nid(value);
#endif
    if (nid == NID_undef)
        return 0;
    *ptype = nid;
    return 1;
}

__owur static int parse_expected_tmp_key_type(tls_TEST_CTX *test_ctx,
                                              const char *value)
{
    return parse_expected_key_type(&test_ctx->expected_tmp_key_type, value);
}

__owur static int parse_expected_server_cert_type(tls_TEST_CTX *test_ctx,
                                                  const char *value)
{
    return parse_expected_key_type(&test_ctx->expected_server_cert_type,
                                   value);
}

__owur static int parse_expected_server_sign_type(tls_TEST_CTX *test_ctx,
                                                 const char *value)
{
    return parse_expected_key_type(&test_ctx->expected_server_sign_type,
                                   value);
}

__owur static int parse_expected_client_cert_type(tls_TEST_CTX *test_ctx,
                                                  const char *value)
{
    return parse_expected_key_type(&test_ctx->expected_client_cert_type,
                                   value);
}

__owur static int parse_expected_client_sign_type(tls_TEST_CTX *test_ctx,
                                                 const char *value)
{
    return parse_expected_key_type(&test_ctx->expected_client_sign_type,
                                   value);
}


/* Expected signing hash */

__owur static int parse_expected_sign_hash(int *ptype, const char *value)
{
    int nid;

    if (value == NULL)
        return 0;
    nid = OBJ_sn2nid(value);
    if (nid == NID_undef)
        nid = OBJ_ln2nid(value);
    if (nid == NID_undef)
        return 0;
    *ptype = nid;
    return 1;
}

__owur static int parse_expected_server_sign_hash(tls_TEST_CTX *test_ctx,
                                                  const char *value)
{
    return parse_expected_sign_hash(&test_ctx->expected_server_sign_hash,
                                    value);
}

__owur static int parse_expected_client_sign_hash(tls_TEST_CTX *test_ctx,
                                                  const char *value)
{
    return parse_expected_sign_hash(&test_ctx->expected_client_sign_hash,
                                    value);
}

__owur static int parse_expected_ca_names(STACK_OF(X509_NAME) **pnames,
                                          const char *value)
{
    if (value == NULL)
        return 0;
    if (!strcmp(value, "empty"))
        *pnames = sk_X509_NAME_new_null();
    else
        *pnames = tls_load_client_CA_file(value);
    return *pnames != NULL;
}
__owur static int parse_expected_server_ca_names(tls_TEST_CTX *test_ctx,
                                                 const char *value)
{
    return parse_expected_ca_names(&test_ctx->expected_server_ca_names, value);
}
__owur static int parse_expected_client_ca_names(tls_TEST_CTX *test_ctx,
                                                 const char *value)
{
    return parse_expected_ca_names(&test_ctx->expected_client_ca_names, value);
}

/* ExpectedCipher */

IMPLEMENT_tls_TEST_STRING_OPTION(tls_TEST_CTX, test, expected_cipher)

/* Client and Server PHA */

IMPLEMENT_tls_TEST_BOOL_OPTION(tls_TEST_CLIENT_CONF, client, enable_pha)
IMPLEMENT_tls_TEST_BOOL_OPTION(tls_TEST_SERVER_CONF, server, force_pha)

/* Known test options and their corresponding parse methods. */

/* Top-level options. */
typedef struct {
    const char *name;
    int (*parse)(tls_TEST_CTX *test_ctx, const char *value);
} tls_test_ctx_option;

static const tls_test_ctx_option tls_test_ctx_options[] = {
    { "ExpectedResult", &parse_expected_result },
    { "ExpectedClientAlert", &parse_client_alert },
    { "ExpectedServerAlert", &parse_server_alert },
    { "ExpectedProtocol", &parse_protocol },
    { "ExpectedServerName", &parse_expected_servername },
    { "SessionTicketExpected", &parse_session_ticket },
    { "CompressionExpected", &parse_test_compression_expected },
    { "SessionIdExpected", &parse_session_id },
    { "Method", &parse_test_method },
    { "ExpectedNPNProtocol", &parse_test_expected_npn_protocol },
    { "ExpectedALPNProtocol", &parse_test_expected_alpn_protocol },
    { "HandshakeMode", &parse_handshake_mode },
    { "KeyUpdateType", &parse_key_update_type },
    { "ResumptionExpected", &parse_test_resumption_expected },
    { "ApplicationData", &parse_test_app_data_size },
    { "MaxFragmentSize", &parse_test_max_fragment_size },
    { "ExpectedTmpKeyType", &parse_expected_tmp_key_type },
    { "ExpectedServerCertType", &parse_expected_server_cert_type },
    { "ExpectedServerSignHash", &parse_expected_server_sign_hash },
    { "ExpectedServerSignType", &parse_expected_server_sign_type },
    { "ExpectedServerCANames", &parse_expected_server_ca_names },
    { "ExpectedClientCertType", &parse_expected_client_cert_type },
    { "ExpectedClientSignHash", &parse_expected_client_sign_hash },
    { "ExpectedClientSignType", &parse_expected_client_sign_type },
    { "ExpectedClientCANames", &parse_expected_client_ca_names },
    { "UseSCTP", &parse_test_use_sctp },
    { "EnableClientSCTPLabelBug", &parse_test_enable_client_sctp_label_bug },
    { "EnableServerSCTPLabelBug", &parse_test_enable_server_sctp_label_bug },
    { "ExpectedCipher", &parse_test_expected_cipher },
    { "ExpectedSessionTicketAppData", &parse_test_expected_session_ticket_app_data },
};

/* Nested client options. */
typedef struct {
    const char *name;
    int (*parse)(tls_TEST_CLIENT_CONF *conf, const char *value);
} tls_test_client_option;

static const tls_test_client_option tls_test_client_options[] = {
    { "VerifyCallback", &parse_client_verify_callback },
    { "ServerName", &parse_servername },
    { "NPNProtocols", &parse_client_npn_protocols },
    { "ALPNProtocols", &parse_client_alpn_protocols },
    { "CTValidation", &parse_ct_validation },
    { "RenegotiateCiphers", &parse_client_reneg_ciphers},
    { "SRPUser", &parse_client_srp_user },
    { "SRPPassword", &parse_client_srp_password },
    { "MaxFragmentLenExt", &parse_max_fragment_len_mode },
    { "EnablePHA", &parse_client_enable_pha },
};

/* Nested server options. */
typedef struct {
    const char *name;
    int (*parse)(tls_TEST_SERVER_CONF *conf, const char *value);
} tls_test_server_option;

static const tls_test_server_option tls_test_server_options[] = {
    { "ServerNameCallback", &parse_servername_callback },
    { "NPNProtocols", &parse_server_npn_protocols },
    { "ALPNProtocols", &parse_server_alpn_protocols },
    { "BrokenSessionTicket", &parse_server_broken_session_ticket },
    { "CertStatus", &parse_certstatus },
    { "SRPUser", &parse_server_srp_user },
    { "SRPPassword", &parse_server_srp_password },
    { "ForcePHA", &parse_server_force_pha },
    { "SessionTicketAppData", &parse_server_session_ticket_app_data },
};

tls_TEST_CTX *tls_TEST_CTX_new(void)
{
    tls_TEST_CTX *ret;

    /* The return code is checked by caller */
    if ((ret = OPENtls_zalloc(sizeof(*ret))) != NULL) {
        ret->app_data_size = default_app_data_size;
        ret->max_fragment_size = default_max_fragment_size;
    }
    return ret;
}

static void tls_test_extra_conf_free_data(tls_TEST_EXTRA_CONF *conf)
{
    OPENtls_free(conf->client.npn_protocols);
    OPENtls_free(conf->server.npn_protocols);
    OPENtls_free(conf->server2.npn_protocols);
    OPENtls_free(conf->client.alpn_protocols);
    OPENtls_free(conf->server.alpn_protocols);
    OPENtls_free(conf->server2.alpn_protocols);
    OPENtls_free(conf->client.reneg_ciphers);
    OPENtls_free(conf->server.srp_user);
    OPENtls_free(conf->server.srp_password);
    OPENtls_free(conf->server2.srp_user);
    OPENtls_free(conf->server2.srp_password);
    OPENtls_free(conf->client.srp_user);
    OPENtls_free(conf->client.srp_password);
    OPENtls_free(conf->server.session_ticket_app_data);
    OPENtls_free(conf->server2.session_ticket_app_data);
}

static void tls_test_ctx_free_extra_data(tls_TEST_CTX *ctx)
{
    tls_test_extra_conf_free_data(&ctx->extra);
    tls_test_extra_conf_free_data(&ctx->resume_extra);
}

void tls_TEST_CTX_free(tls_TEST_CTX *ctx)
{
    tls_test_ctx_free_extra_data(ctx);
    OPENtls_free(ctx->expected_npn_protocol);
    OPENtls_free(ctx->expected_alpn_protocol);
    OPENtls_free(ctx->expected_session_ticket_app_data);
    sk_X509_NAME_pop_free(ctx->expected_server_ca_names, X509_NAME_free);
    sk_X509_NAME_pop_free(ctx->expected_client_ca_names, X509_NAME_free);
    OPENtls_free(ctx->expected_cipher);
    OPENtls_free(ctx);
}

static int parse_client_options(tls_TEST_CLIENT_CONF *client, const CONF *conf,
                                const char *client_section)
{
    STACK_OF(CONF_VALUE) *sk_conf;
    int i;
    size_t j;

    if (!TEST_ptr(sk_conf = NCONF_get_section(conf, client_section)))
        return 0;

    for (i = 0; i < sk_CONF_VALUE_num(sk_conf); i++) {
        int found = 0;
        const CONF_VALUE *option = sk_CONF_VALUE_value(sk_conf, i);
        for (j = 0; j < Otls_NELEM(tls_test_client_options); j++) {
            if (strcmp(option->name, tls_test_client_options[j].name) == 0) {
                if (!tls_test_client_options[j].parse(client, option->value)) {
                    TEST_info("Bad value %s for option %s",
                              option->value, option->name);
                    return 0;
                }
                found = 1;
                break;
            }
        }
        if (!found) {
            TEST_info("Unknown test option: %s", option->name);
            return 0;
        }
    }

    return 1;
}

static int parse_server_options(tls_TEST_SERVER_CONF *server, const CONF *conf,
                                const char *server_section)
{
    STACK_OF(CONF_VALUE) *sk_conf;
    int i;
    size_t j;

    if (!TEST_ptr(sk_conf = NCONF_get_section(conf, server_section)))
        return 0;

    for (i = 0; i < sk_CONF_VALUE_num(sk_conf); i++) {
        int found = 0;
        const CONF_VALUE *option = sk_CONF_VALUE_value(sk_conf, i);
        for (j = 0; j < Otls_NELEM(tls_test_server_options); j++) {
            if (strcmp(option->name, tls_test_server_options[j].name) == 0) {
                if (!tls_test_server_options[j].parse(server, option->value)) {
                    TEST_info("Bad value %s for option %s",
                               option->value, option->name);
                    return 0;
                }
                found = 1;
                break;
            }
        }
        if (!found) {
            TEST_info("Unknown test option: %s", option->name);
            return 0;
        }
    }

    return 1;
}

tls_TEST_CTX *tls_TEST_CTX_create(const CONF *conf, const char *test_section)
{
    STACK_OF(CONF_VALUE) *sk_conf = NULL;
    tls_TEST_CTX *ctx = NULL;
    int i;
    size_t j;

    if (!TEST_ptr(sk_conf = NCONF_get_section(conf, test_section))
            || !TEST_ptr(ctx = tls_TEST_CTX_new()))
        goto err;

    for (i = 0; i < sk_CONF_VALUE_num(sk_conf); i++) {
        int found = 0;
        const CONF_VALUE *option = sk_CONF_VALUE_value(sk_conf, i);

        /* Subsections */
        if (strcmp(option->name, "client") == 0) {
            if (!parse_client_options(&ctx->extra.client, conf, option->value))
                goto err;
        } else if (strcmp(option->name, "server") == 0) {
            if (!parse_server_options(&ctx->extra.server, conf, option->value))
                goto err;
        } else if (strcmp(option->name, "server2") == 0) {
            if (!parse_server_options(&ctx->extra.server2, conf, option->value))
                goto err;
        } else if (strcmp(option->name, "resume-client") == 0) {
            if (!parse_client_options(&ctx->resume_extra.client, conf,
                                      option->value))
                goto err;
        } else if (strcmp(option->name, "resume-server") == 0) {
            if (!parse_server_options(&ctx->resume_extra.server, conf,
                                      option->value))
                goto err;
        } else if (strcmp(option->name, "resume-server2") == 0) {
            if (!parse_server_options(&ctx->resume_extra.server2, conf,
                                      option->value))
                goto err;
        } else {
            for (j = 0; j < Otls_NELEM(tls_test_ctx_options); j++) {
                if (strcmp(option->name, tls_test_ctx_options[j].name) == 0) {
                    if (!tls_test_ctx_options[j].parse(ctx, option->value)) {
                        TEST_info("Bad value %s for option %s",
                                   option->value, option->name);
                        goto err;
                    }
                    found = 1;
                    break;
                }
            }
            if (!found) {
                TEST_info("Unknown test option: %s", option->name);
                goto err;
            }
        }
    }

    goto done;

 err:
    tls_TEST_CTX_free(ctx);
    ctx = NULL;
 done:
    return ctx;
}
