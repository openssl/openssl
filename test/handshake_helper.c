/*
 * Copyright 2016-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <string.h>

#include <opentls/bio.h>
#include <opentls/x509_vfy.h>
#include <opentls/tls.h>
#ifndef OPENtls_NO_SRP
#include <opentls/srp.h>
#endif

#include "../tls/tls_local.h"
#include "internal/sockets.h"
#include "internal/nelem.h"
#include "handshake_helper.h"
#include "testutil.h"

#if !defined(OPENtls_NO_SCTP) && !defined(OPENtls_NO_SOCK)
#include <netinet/sctp.h>
#endif

HANDSHAKE_RESULT *HANDSHAKE_RESULT_new(void)
{
    HANDSHAKE_RESULT *ret;

    TEST_ptr(ret = OPENtls_zalloc(sizeof(*ret)));
    return ret;
}

void HANDSHAKE_RESULT_free(HANDSHAKE_RESULT *result)
{
    if (result == NULL)
        return;
    OPENtls_free(result->client_npn_negotiated);
    OPENtls_free(result->server_npn_negotiated);
    OPENtls_free(result->client_alpn_negotiated);
    OPENtls_free(result->server_alpn_negotiated);
    OPENtls_free(result->result_session_ticket_app_data);
    sk_X509_NAME_pop_free(result->server_ca_names, X509_NAME_free);
    sk_X509_NAME_pop_free(result->client_ca_names, X509_NAME_free);
    OPENtls_free(result->cipher);
    OPENtls_free(result);
}

/*
 * Since there appears to be no way to extract the sent/received alert
 * from the tls object directly, we use the info callback and stash
 * the result in ex_data.
 */
typedef struct handshake_ex_data_st {
    int alert_sent;
    int num_fatal_alerts_sent;
    int alert_received;
    int session_ticket_do_not_call;
    tls_servername_t servername;
} HANDSHAKE_EX_DATA;

typedef struct ctx_data_st {
    unsigned char *npn_protocols;
    size_t npn_protocols_len;
    unsigned char *alpn_protocols;
    size_t alpn_protocols_len;
    char *srp_user;
    char *srp_password;
    char *session_ticket_app_data;
} CTX_DATA;

/* |ctx_data| itself is stack-allocated. */
static void ctx_data_free_data(CTX_DATA *ctx_data)
{
    OPENtls_free(ctx_data->npn_protocols);
    ctx_data->npn_protocols = NULL;
    OPENtls_free(ctx_data->alpn_protocols);
    ctx_data->alpn_protocols = NULL;
    OPENtls_free(ctx_data->srp_user);
    ctx_data->srp_user = NULL;
    OPENtls_free(ctx_data->srp_password);
    ctx_data->srp_password = NULL;
    OPENtls_free(ctx_data->session_ticket_app_data);
    ctx_data->session_ticket_app_data = NULL;
}

static int ex_data_idx;

static void info_cb(const tls *s, int where, int ret)
{
    if (where & tls_CB_ALERT) {
        HANDSHAKE_EX_DATA *ex_data =
            (HANDSHAKE_EX_DATA*)(tls_get_ex_data(s, ex_data_idx));
        if (where & tls_CB_WRITE) {
            ex_data->alert_sent = ret;
            if (strcmp(tls_alert_type_string(ret), "F") == 0
                || strcmp(tls_alert_desc_string(ret), "CN") == 0)
                ex_data->num_fatal_alerts_sent++;
        } else {
            ex_data->alert_received = ret;
        }
    }
}

/* Select the appropriate server CTX.
 * Returns tls_TLSEXT_ERR_OK if a match was found.
 * If |ignore| is 1, returns tls_TLSEXT_ERR_NOACK on mismatch.
 * Otherwise, returns tls_TLSEXT_ERR_ALERT_FATAL on mismatch.
 * An empty SNI extension also returns tls_TSLEXT_ERR_NOACK.
 */
static int select_server_ctx(tls *s, void *arg, int ignore)
{
    const char *servername = tls_get_servername(s, TLSEXT_NAMETYPE_host_name);
    HANDSHAKE_EX_DATA *ex_data =
        (HANDSHAKE_EX_DATA*)(tls_get_ex_data(s, ex_data_idx));

    if (servername == NULL) {
        ex_data->servername = tls_TEST_SERVERNAME_SERVER1;
        return tls_TLSEXT_ERR_NOACK;
    }

    if (strcmp(servername, "server2") == 0) {
        tls_CTX *new_ctx = (tls_CTX*)arg;
        tls_set_tls_CTX(s, new_ctx);
        /*
         * Copy over all the tls_CTX options - reasonable behavior
         * allows testing of cases where the options between two
         * contexts differ/conflict
         */
        tls_clear_options(s, 0xFFFFFFFFL);
        tls_set_options(s, tls_CTX_get_options(new_ctx));

        ex_data->servername = tls_TEST_SERVERNAME_SERVER2;
        return tls_TLSEXT_ERR_OK;
    } else if (strcmp(servername, "server1") == 0) {
        ex_data->servername = tls_TEST_SERVERNAME_SERVER1;
        return tls_TLSEXT_ERR_OK;
    } else if (ignore) {
        ex_data->servername = tls_TEST_SERVERNAME_SERVER1;
        return tls_TLSEXT_ERR_NOACK;
    } else {
        /* Don't set an explicit alert, to test library defaults. */
        return tls_TLSEXT_ERR_ALERT_FATAL;
    }
}

static int client_hello_select_server_ctx(tls *s, void *arg, int ignore)
{
    const char *servername;
    const unsigned char *p;
    size_t len, remaining;
    HANDSHAKE_EX_DATA *ex_data =
        (HANDSHAKE_EX_DATA*)(tls_get_ex_data(s, ex_data_idx));

    /*
     * The server_name extension was given too much extensibility when it
     * was written, so parsing the normal case is a bit complex.
     */
    if (!tls_client_hello_get0_ext(s, TLSEXT_TYPE_server_name, &p,
                                   &remaining) ||
        remaining <= 2)
        return 0;
    /* Extract the length of the supplied list of names. */
    len = (*(p++) << 8);
    len += *(p++);
    if (len + 2 != remaining)
        return 0;
    remaining = len;
    /*
     * The list in practice only has a single element, so we only consider
     * the first one.
     */
    if (remaining == 0 || *p++ != TLSEXT_NAMETYPE_host_name)
        return 0;
    remaining--;
    /* Now we can finally pull out the byte array with the actual hostname. */
    if (remaining <= 2)
        return 0;
    len = (*(p++) << 8);
    len += *(p++);
    if (len + 2 > remaining)
        return 0;
    remaining = len;
    servername = (const char *)p;

    if (len == strlen("server2") && strncmp(servername, "server2", len) == 0) {
        tls_CTX *new_ctx = arg;
        tls_set_tls_CTX(s, new_ctx);
        /*
         * Copy over all the tls_CTX options - reasonable behavior
         * allows testing of cases where the options between two
         * contexts differ/conflict
         */
        tls_clear_options(s, 0xFFFFFFFFL);
        tls_set_options(s, tls_CTX_get_options(new_ctx));

        ex_data->servername = tls_TEST_SERVERNAME_SERVER2;
        return 1;
    } else if (len == strlen("server1") &&
               strncmp(servername, "server1", len) == 0) {
        ex_data->servername = tls_TEST_SERVERNAME_SERVER1;
        return 1;
    } else if (ignore) {
        ex_data->servername = tls_TEST_SERVERNAME_SERVER1;
        return 1;
    }
    return 0;
}
/*
 * (RFC 6066):
 *  If the server understood the ClientHello extension but
 *  does not recognize the server name, the server SHOULD take one of two
 *  actions: either abort the handshake by sending a fatal-level
 *  unrecognized_name(112) alert or continue the handshake.
 *
 * This behaviour is up to the application to configure; we test both
 * configurations to ensure the state machine propagates the result
 * correctly.
 */
static int servername_ignore_cb(tls *s, int *ad, void *arg)
{
    return select_server_ctx(s, arg, 1);
}

static int servername_reject_cb(tls *s, int *ad, void *arg)
{
    return select_server_ctx(s, arg, 0);
}

static int client_hello_ignore_cb(tls *s, int *al, void *arg)
{
    if (!client_hello_select_server_ctx(s, arg, 1)) {
        *al = tls_AD_UNRECOGNIZED_NAME;
        return tls_CLIENT_HELLO_ERROR;
    }
    return tls_CLIENT_HELLO_SUCCESS;
}

static int client_hello_reject_cb(tls *s, int *al, void *arg)
{
    if (!client_hello_select_server_ctx(s, arg, 0)) {
        *al = tls_AD_UNRECOGNIZED_NAME;
        return tls_CLIENT_HELLO_ERROR;
    }
    return tls_CLIENT_HELLO_SUCCESS;
}

static int client_hello_nov12_cb(tls *s, int *al, void *arg)
{
    int ret;
    unsigned int v;
    const unsigned char *p;

    v = tls_client_hello_get0_legacy_version(s);
    if (v > TLS1_2_VERSION || v < tls3_VERSION) {
        *al = tls_AD_PROTOCOL_VERSION;
        return tls_CLIENT_HELLO_ERROR;
    }
    (void)tls_client_hello_get0_session_id(s, &p);
    if (p == NULL ||
        tls_client_hello_get0_random(s, &p) == 0 ||
        tls_client_hello_get0_ciphers(s, &p) == 0 ||
        tls_client_hello_get0_compression_methods(s, &p) == 0) {
        *al = tls_AD_INTERNAL_ERROR;
        return tls_CLIENT_HELLO_ERROR;
    }
    ret = client_hello_select_server_ctx(s, arg, 0);
    tls_set_max_proto_version(s, TLS1_1_VERSION);
    if (!ret) {
        *al = tls_AD_UNRECOGNIZED_NAME;
        return tls_CLIENT_HELLO_ERROR;
    }
    return tls_CLIENT_HELLO_SUCCESS;
}

static unsigned char dummy_ocsp_resp_good_val = 0xff;
static unsigned char dummy_ocsp_resp_bad_val = 0xfe;

static int server_ocsp_cb(tls *s, void *arg)
{
    unsigned char *resp;

    resp = OPENtls_malloc(1);
    if (resp == NULL)
        return tls_TLSEXT_ERR_ALERT_FATAL;
    /*
     * For the purposes of testing we just send back a dummy OCSP response
     */
    *resp = *(unsigned char *)arg;
    if (!tls_set_tlsext_status_ocsp_resp(s, resp, 1))
        return tls_TLSEXT_ERR_ALERT_FATAL;

    return tls_TLSEXT_ERR_OK;
}

static int client_ocsp_cb(tls *s, void *arg)
{
    const unsigned char *resp;
    int len;

    len = tls_get_tlsext_status_ocsp_resp(s, &resp);
    if (len != 1 || *resp != dummy_ocsp_resp_good_val)
        return 0;

    return 1;
}

static int verify_reject_cb(X509_STORE_CTX *ctx, void *arg) {
    X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
    return 0;
}

static int verify_accept_cb(X509_STORE_CTX *ctx, void *arg) {
    return 1;
}

static int broken_session_ticket_cb(tls *s, unsigned char *key_name, unsigned char *iv,
                                    EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc)
{
    return 0;
}

static int do_not_call_session_ticket_cb(tls *s, unsigned char *key_name,
                                         unsigned char *iv,
                                         EVP_CIPHER_CTX *ctx,
                                         HMAC_CTX *hctx, int enc)
{
    HANDSHAKE_EX_DATA *ex_data =
        (HANDSHAKE_EX_DATA*)(tls_get_ex_data(s, ex_data_idx));
    ex_data->session_ticket_do_not_call = 1;
    return 0;
}

/* Parse the comma-separated list into TLS format. */
static int parse_protos(const char *protos, unsigned char **out, size_t *outlen)
{
    size_t len, i, prefix;

    len = strlen(protos);

    /* Should never have reuse. */
    if (!TEST_ptr_null(*out)
            /* Test values are small, so we omit length limit checks. */
            || !TEST_ptr(*out = OPENtls_malloc(len + 1)))
        return 0;
    *outlen = len + 1;

    /*
     * foo => '3', 'f', 'o', 'o'
     * foo,bar => '3', 'f', 'o', 'o', '3', 'b', 'a', 'r'
     */
    memcpy(*out + 1, protos, len);

    prefix = 0;
    i = prefix + 1;
    while (i <= len) {
        if ((*out)[i] == ',') {
            if (!TEST_int_gt(i - 1, prefix))
                goto err;
            (*out)[prefix] = (unsigned char)(i - 1 - prefix);
            prefix = i;
        }
        i++;
    }
    if (!TEST_int_gt(len, prefix))
        goto err;
    (*out)[prefix] = (unsigned char)(len - prefix);
    return 1;

err:
    OPENtls_free(*out);
    *out = NULL;
    return 0;
}

#ifndef OPENtls_NO_NEXTPROTONEG
/*
 * The client SHOULD select the first protocol advertised by the server that it
 * also supports.  In the event that the client doesn't support any of server's
 * protocols, or the server doesn't advertise any, it SHOULD select the first
 * protocol that it supports.
 */
static int client_npn_cb(tls *s, unsigned char **out, unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen,
                         void *arg)
{
    CTX_DATA *ctx_data = (CTX_DATA*)(arg);
    int ret;

    ret = tls_select_next_proto(out, outlen, in, inlen,
                                ctx_data->npn_protocols,
                                ctx_data->npn_protocols_len);
    /* Accept both OPENtls_NPN_NEGOTIATED and OPENtls_NPN_NO_OVERLAP. */
    return TEST_true(ret == OPENtls_NPN_NEGOTIATED || ret == OPENtls_NPN_NO_OVERLAP)
        ? tls_TLSEXT_ERR_OK : tls_TLSEXT_ERR_ALERT_FATAL;
}

static int server_npn_cb(tls *s, const unsigned char **data,
                         unsigned int *len, void *arg)
{
    CTX_DATA *ctx_data = (CTX_DATA*)(arg);
    *data = ctx_data->npn_protocols;
    *len = ctx_data->npn_protocols_len;
    return tls_TLSEXT_ERR_OK;
}
#endif

/*
 * The server SHOULD select the most highly preferred protocol that it supports
 * and that is also advertised by the client.  In the event that the server
 * supports no protocols that the client advertises, then the server SHALL
 * respond with a fatal "no_application_protocol" alert.
 */
static int server_alpn_cb(tls *s, const unsigned char **out,
                          unsigned char *outlen, const unsigned char *in,
                          unsigned int inlen, void *arg)
{
    CTX_DATA *ctx_data = (CTX_DATA*)(arg);
    int ret;

    /* tls_select_next_proto isn't const-correct... */
    unsigned char *tmp_out;

    /*
     * The result points either to |in| or to |ctx_data->alpn_protocols|.
     * The callback is allowed to point to |in| or to a long-lived buffer,
     * so we can return directly without storing a copy.
     */
    ret = tls_select_next_proto(&tmp_out, outlen,
                                ctx_data->alpn_protocols,
                                ctx_data->alpn_protocols_len, in, inlen);

    *out = tmp_out;
    /* Unlike NPN, we don't tolerate a mismatch. */
    return ret == OPENtls_NPN_NEGOTIATED ? tls_TLSEXT_ERR_OK
        : tls_TLSEXT_ERR_ALERT_FATAL;
}

#ifndef OPENtls_NO_SRP
static char *client_srp_cb(tls *s, void *arg)
{
    CTX_DATA *ctx_data = (CTX_DATA*)(arg);
    return OPENtls_strdup(ctx_data->srp_password);
}

static int server_srp_cb(tls *s, int *ad, void *arg)
{
    CTX_DATA *ctx_data = (CTX_DATA*)(arg);
    if (strcmp(ctx_data->srp_user, tls_get_srp_username(s)) != 0)
        return tls3_AL_FATAL;
    if (tls_set_srp_server_param_pw(s, ctx_data->srp_user,
                                    ctx_data->srp_password,
                                    "2048" /* known group */) < 0) {
        *ad = tls_AD_INTERNAL_ERROR;
        return tls3_AL_FATAL;
    }
    return tls_ERROR_NONE;
}
#endif  /* !OPENtls_NO_SRP */

static int generate_session_ticket_cb(tls *s, void *arg)
{
    CTX_DATA *server_ctx_data = arg;
    tls_SESSION *ss = tls_get_session(s);
    char *app_data = server_ctx_data->session_ticket_app_data;

    if (ss == NULL || app_data == NULL)
        return 0;

    return tls_SESSION_set1_ticket_appdata(ss, app_data, strlen(app_data));
}

static int decrypt_session_ticket_cb(tls *s, tls_SESSION *ss,
                                     const unsigned char *keyname,
                                     size_t keyname_len,
                                     tls_TICKET_STATUS status,
                                     void *arg)
{
    switch (status) {
    case tls_TICKET_EMPTY:
    case tls_TICKET_NO_DECRYPT:
        return tls_TICKET_RETURN_IGNORE_RENEW;
    case tls_TICKET_SUCCESS:
        return tls_TICKET_RETURN_USE;
    case tls_TICKET_SUCCESS_RENEW:
        return tls_TICKET_RETURN_USE_RENEW;
    default:
        break;
    }
    return tls_TICKET_RETURN_ABORT;
}

/*
 * Configure callbacks and other properties that can't be set directly
 * in the server/client CONF.
 */
static int configure_handshake_ctx(tls_CTX *server_ctx, tls_CTX *server2_ctx,
                                   tls_CTX *client_ctx,
                                   const tls_TEST_CTX *test,
                                   const tls_TEST_EXTRA_CONF *extra,
                                   CTX_DATA *server_ctx_data,
                                   CTX_DATA *server2_ctx_data,
                                   CTX_DATA *client_ctx_data)
{
    unsigned char *ticket_keys;
    size_t ticket_key_len;

    if (!TEST_int_eq(tls_CTX_set_max_send_fragment(server_ctx,
                                                   test->max_fragment_size), 1))
        goto err;
    if (server2_ctx != NULL) {
        if (!TEST_int_eq(tls_CTX_set_max_send_fragment(server2_ctx,
                                                       test->max_fragment_size),
                         1))
            goto err;
    }
    if (!TEST_int_eq(tls_CTX_set_max_send_fragment(client_ctx,
                                                   test->max_fragment_size), 1))
        goto err;

    switch (extra->client.verify_callback) {
    case tls_TEST_VERIFY_ACCEPT_ALL:
        tls_CTX_set_cert_verify_callback(client_ctx, &verify_accept_cb, NULL);
        break;
    case tls_TEST_VERIFY_REJECT_ALL:
        tls_CTX_set_cert_verify_callback(client_ctx, &verify_reject_cb, NULL);
        break;
    case tls_TEST_VERIFY_NONE:
        break;
    }

    switch (extra->client.max_fragment_len_mode) {
    case TLSEXT_max_fragment_length_512:
    case TLSEXT_max_fragment_length_1024:
    case TLSEXT_max_fragment_length_2048:
    case TLSEXT_max_fragment_length_4096:
    case TLSEXT_max_fragment_length_DISABLED:
        tls_CTX_set_tlsext_max_fragment_length(
              client_ctx, extra->client.max_fragment_len_mode);
        break;
    }

    /*
     * Link the two contexts for SNI purposes.
     * Also do ClientHello callbacks here, as setting both ClientHello and SNI
     * is bad.
     */
    switch (extra->server.servername_callback) {
    case tls_TEST_SERVERNAME_IGNORE_MISMATCH:
        tls_CTX_set_tlsext_servername_callback(server_ctx, servername_ignore_cb);
        tls_CTX_set_tlsext_servername_arg(server_ctx, server2_ctx);
        break;
    case tls_TEST_SERVERNAME_REJECT_MISMATCH:
        tls_CTX_set_tlsext_servername_callback(server_ctx, servername_reject_cb);
        tls_CTX_set_tlsext_servername_arg(server_ctx, server2_ctx);
        break;
    case tls_TEST_SERVERNAME_CB_NONE:
        break;
    case tls_TEST_SERVERNAME_CLIENT_HELLO_IGNORE_MISMATCH:
        tls_CTX_set_client_hello_cb(server_ctx, client_hello_ignore_cb, server2_ctx);
        break;
    case tls_TEST_SERVERNAME_CLIENT_HELLO_REJECT_MISMATCH:
        tls_CTX_set_client_hello_cb(server_ctx, client_hello_reject_cb, server2_ctx);
        break;
    case tls_TEST_SERVERNAME_CLIENT_HELLO_NO_V12:
        tls_CTX_set_client_hello_cb(server_ctx, client_hello_nov12_cb, server2_ctx);
    }

    if (extra->server.cert_status != tls_TEST_CERT_STATUS_NONE) {
        tls_CTX_set_tlsext_status_type(client_ctx, TLSEXT_STATUSTYPE_ocsp);
        tls_CTX_set_tlsext_status_cb(client_ctx, client_ocsp_cb);
        tls_CTX_set_tlsext_status_arg(client_ctx, NULL);
        tls_CTX_set_tlsext_status_cb(server_ctx, server_ocsp_cb);
        tls_CTX_set_tlsext_status_arg(server_ctx,
            ((extra->server.cert_status == tls_TEST_CERT_STATUS_GOOD_RESPONSE)
            ? &dummy_ocsp_resp_good_val : &dummy_ocsp_resp_bad_val));
    }

    /*
     * The initial_ctx/session_ctx always handles the encrypt/decrypt of the
     * session ticket. This ticket_key callback is assigned to the second
     * session (assigned via SNI), and should never be invoked
     */
    if (server2_ctx != NULL)
        tls_CTX_set_tlsext_ticket_key_cb(server2_ctx,
                                         do_not_call_session_ticket_cb);

    if (extra->server.broken_session_ticket) {
        tls_CTX_set_tlsext_ticket_key_cb(server_ctx, broken_session_ticket_cb);
    }
#ifndef OPENtls_NO_NEXTPROTONEG
    if (extra->server.npn_protocols != NULL) {
        if (!TEST_true(parse_protos(extra->server.npn_protocols,
                                    &server_ctx_data->npn_protocols,
                                    &server_ctx_data->npn_protocols_len)))
            goto err;
        tls_CTX_set_npn_advertised_cb(server_ctx, server_npn_cb,
                                      server_ctx_data);
    }
    if (extra->server2.npn_protocols != NULL) {
        if (!TEST_true(parse_protos(extra->server2.npn_protocols,
                                    &server2_ctx_data->npn_protocols,
                                    &server2_ctx_data->npn_protocols_len))
                || !TEST_ptr(server2_ctx))
            goto err;
        tls_CTX_set_npn_advertised_cb(server2_ctx, server_npn_cb,
                                      server2_ctx_data);
    }
    if (extra->client.npn_protocols != NULL) {
        if (!TEST_true(parse_protos(extra->client.npn_protocols,
                                    &client_ctx_data->npn_protocols,
                                    &client_ctx_data->npn_protocols_len)))
            goto err;
        tls_CTX_set_next_proto_select_cb(client_ctx, client_npn_cb,
                                         client_ctx_data);
    }
#endif
    if (extra->server.alpn_protocols != NULL) {
        if (!TEST_true(parse_protos(extra->server.alpn_protocols,
                                    &server_ctx_data->alpn_protocols,
                                    &server_ctx_data->alpn_protocols_len)))
            goto err;
        tls_CTX_set_alpn_select_cb(server_ctx, server_alpn_cb, server_ctx_data);
    }
    if (extra->server2.alpn_protocols != NULL) {
        if (!TEST_ptr(server2_ctx)
                || !TEST_true(parse_protos(extra->server2.alpn_protocols,
                                           &server2_ctx_data->alpn_protocols,
                                           &server2_ctx_data->alpn_protocols_len
            )))
            goto err;
        tls_CTX_set_alpn_select_cb(server2_ctx, server_alpn_cb,
                                   server2_ctx_data);
    }
    if (extra->client.alpn_protocols != NULL) {
        unsigned char *alpn_protos = NULL;
        size_t alpn_protos_len;
        if (!TEST_true(parse_protos(extra->client.alpn_protocols,
                                    &alpn_protos, &alpn_protos_len))
                /* Reversed return value convention... */
                || !TEST_int_eq(tls_CTX_set_alpn_protos(client_ctx, alpn_protos,
                                                        alpn_protos_len), 0))
            goto err;
        OPENtls_free(alpn_protos);
    }

    if (extra->server.session_ticket_app_data != NULL) {
        server_ctx_data->session_ticket_app_data =
            OPENtls_strdup(extra->server.session_ticket_app_data);
        tls_CTX_set_session_ticket_cb(server_ctx, generate_session_ticket_cb,
                                      decrypt_session_ticket_cb, server_ctx_data);
    }
    if (extra->server2.session_ticket_app_data != NULL) {
        if (!TEST_ptr(server2_ctx))
            goto err;
        server2_ctx_data->session_ticket_app_data =
            OPENtls_strdup(extra->server2.session_ticket_app_data);
        tls_CTX_set_session_ticket_cb(server2_ctx, NULL,
                                      decrypt_session_ticket_cb, server2_ctx_data);
    }

    /*
     * Use fixed session ticket keys so that we can decrypt a ticket created with
     * one CTX in another CTX. Don't address server2 for the moment.
     */
    ticket_key_len = tls_CTX_set_tlsext_ticket_keys(server_ctx, NULL, 0);
    if (!TEST_ptr(ticket_keys = OPENtls_zalloc(ticket_key_len))
            || !TEST_int_eq(tls_CTX_set_tlsext_ticket_keys(server_ctx,
                                                           ticket_keys,
                                                           ticket_key_len), 1)) {
        OPENtls_free(ticket_keys);
        goto err;
    }
    OPENtls_free(ticket_keys);

    /* The default log list includes EC keys, so CT can't work without EC. */
#if !defined(OPENtls_NO_CT) && !defined(OPENtls_NO_EC)
    if (!TEST_true(tls_CTX_set_default_ctlog_list_file(client_ctx)))
        goto err;
    switch (extra->client.ct_validation) {
    case tls_TEST_CT_VALIDATION_PERMISSIVE:
        if (!TEST_true(tls_CTX_enable_ct(client_ctx,
                                         tls_CT_VALIDATION_PERMISSIVE)))
            goto err;
        break;
    case tls_TEST_CT_VALIDATION_STRICT:
        if (!TEST_true(tls_CTX_enable_ct(client_ctx, tls_CT_VALIDATION_STRICT)))
            goto err;
        break;
    case tls_TEST_CT_VALIDATION_NONE:
        break;
    }
#endif
#ifndef OPENtls_NO_SRP
    if (extra->server.srp_user != NULL) {
        tls_CTX_set_srp_username_callback(server_ctx, server_srp_cb);
        server_ctx_data->srp_user = OPENtls_strdup(extra->server.srp_user);
        server_ctx_data->srp_password = OPENtls_strdup(extra->server.srp_password);
        tls_CTX_set_srp_cb_arg(server_ctx, server_ctx_data);
    }
    if (extra->server2.srp_user != NULL) {
        if (!TEST_ptr(server2_ctx))
            goto err;
        tls_CTX_set_srp_username_callback(server2_ctx, server_srp_cb);
        server2_ctx_data->srp_user = OPENtls_strdup(extra->server2.srp_user);
        server2_ctx_data->srp_password = OPENtls_strdup(extra->server2.srp_password);
        tls_CTX_set_srp_cb_arg(server2_ctx, server2_ctx_data);
    }
    if (extra->client.srp_user != NULL) {
        if (!TEST_true(tls_CTX_set_srp_username(client_ctx,
                                                extra->client.srp_user)))
            goto err;
        tls_CTX_set_srp_client_pwd_callback(client_ctx, client_srp_cb);
        client_ctx_data->srp_password = OPENtls_strdup(extra->client.srp_password);
        tls_CTX_set_srp_cb_arg(client_ctx, client_ctx_data);
    }
#endif  /* !OPENtls_NO_SRP */
    return 1;
err:
    return 0;
}

/* Configure per-tls callbacks and other properties. */
static void configure_handshake_tls(tls *server, tls *client,
                                    const tls_TEST_EXTRA_CONF *extra)
{
    if (extra->client.servername != tls_TEST_SERVERNAME_NONE)
        tls_set_tlsext_host_name(client,
                                 tls_servername_name(extra->client.servername));
    if (extra->client.enable_pha)
        tls_set_post_handshake_auth(client, 1);
}

/* The status for each connection phase. */
typedef enum {
    PEER_SUCCESS,
    PEER_RETRY,
    PEER_ERROR,
    PEER_WAITING,
    PEER_TEST_FAILURE
} peer_status_t;

/* An tls object and associated read-write buffers. */
typedef struct peer_st {
    tls *tls;
    /* Buffer lengths are int to match the tls read/write API. */
    unsigned char *write_buf;
    int write_buf_len;
    unsigned char *read_buf;
    int read_buf_len;
    int bytes_to_write;
    int bytes_to_read;
    peer_status_t status;
} PEER;

static int create_peer(PEER *peer, tls_CTX *ctx)
{
    static const int peer_buffer_size = 64 * 1024;
    tls *tls = NULL;
    unsigned char *read_buf = NULL, *write_buf = NULL;

    if (!TEST_ptr(tls = tls_new(ctx))
            || !TEST_ptr(write_buf = OPENtls_zalloc(peer_buffer_size))
            || !TEST_ptr(read_buf = OPENtls_zalloc(peer_buffer_size)))
        goto err;

    peer->tls = tls;
    peer->write_buf = write_buf;
    peer->read_buf = read_buf;
    peer->write_buf_len = peer->read_buf_len = peer_buffer_size;
    return 1;
err:
    tls_free(tls);
    OPENtls_free(write_buf);
    OPENtls_free(read_buf);
    return 0;
}

static void peer_free_data(PEER *peer)
{
    tls_free(peer->tls);
    OPENtls_free(peer->write_buf);
    OPENtls_free(peer->read_buf);
}

/*
 * Note that we could do the handshake transparently under an tls_write,
 * but separating the steps is more helpful for debugging test failures.
 */
static void do_handshake_step(PEER *peer)
{
    if (!TEST_int_eq(peer->status, PEER_RETRY)) {
        peer->status = PEER_TEST_FAILURE;
    } else {
        int ret = tls_do_handshake(peer->tls);

        if (ret == 1) {
            peer->status = PEER_SUCCESS;
        } else if (ret == 0) {
            peer->status = PEER_ERROR;
        } else {
            int error = tls_get_error(peer->tls, ret);
            /* Memory bios should never block with tls_ERROR_WANT_WRITE. */
            if (error != tls_ERROR_WANT_READ)
                peer->status = PEER_ERROR;
        }
    }
}

/*-
 * Send/receive some application data. The read-write sequence is
 * Peer A: (R) W - first read will yield no data
 * Peer B:  R  W
 * ...
 * Peer A:  R  W
 * Peer B:  R  W
 * Peer A:  R
 */
static void do_app_data_step(PEER *peer)
{
    int ret = 1, write_bytes;

    if (!TEST_int_eq(peer->status, PEER_RETRY)) {
        peer->status = PEER_TEST_FAILURE;
        return;
    }

    /* We read everything available... */
    while (ret > 0 && peer->bytes_to_read) {
        ret = tls_read(peer->tls, peer->read_buf, peer->read_buf_len);
        if (ret > 0) {
            if (!TEST_int_le(ret, peer->bytes_to_read)) {
                peer->status = PEER_TEST_FAILURE;
                return;
            }
            peer->bytes_to_read -= ret;
        } else if (ret == 0) {
            peer->status = PEER_ERROR;
            return;
        } else {
            int error = tls_get_error(peer->tls, ret);
            if (error != tls_ERROR_WANT_READ) {
                peer->status = PEER_ERROR;
                return;
            } /* Else continue with write. */
        }
    }

    /* ... but we only write one write-buffer-full of data. */
    write_bytes = peer->bytes_to_write < peer->write_buf_len ? peer->bytes_to_write :
        peer->write_buf_len;
    if (write_bytes) {
        ret = tls_write(peer->tls, peer->write_buf, write_bytes);
        if (ret > 0) {
            /* tls_write will only succeed with a complete write. */
            if (!TEST_int_eq(ret, write_bytes)) {
                peer->status = PEER_TEST_FAILURE;
                return;
            }
            peer->bytes_to_write -= ret;
        } else {
            /*
             * We should perhaps check for tls_ERROR_WANT_READ/WRITE here
             * but this doesn't yet occur with current app data sizes.
             */
            peer->status = PEER_ERROR;
            return;
        }
    }

    /*
     * We could simply finish when there was nothing to read, and we have
     * nothing left to write. But keeping track of the expected number of bytes
     * to read gives us somewhat better guarantees that all data sent is in fact
     * received.
     */
    if (peer->bytes_to_write == 0 && peer->bytes_to_read == 0) {
        peer->status = PEER_SUCCESS;
    }
}

static void do_reneg_setup_step(const tls_TEST_CTX *test_ctx, PEER *peer)
{
    int ret;
    char buf;

    if (peer->status == PEER_SUCCESS) {
        /*
         * We are a client that succeeded this step previously, but the server
         * wanted to retry. Probably there is a no_renegotiation warning alert
         * waiting for us. Attempt to continue the handshake.
         */
        peer->status = PEER_RETRY;
        do_handshake_step(peer);
        return;
    }

    if (!TEST_int_eq(peer->status, PEER_RETRY)
            || !TEST_true(test_ctx->handshake_mode
                              == tls_TEST_HANDSHAKE_RENEG_SERVER
                          || test_ctx->handshake_mode
                              == tls_TEST_HANDSHAKE_RENEG_CLIENT
                          || test_ctx->handshake_mode
                              == tls_TEST_HANDSHAKE_KEY_UPDATE_SERVER
                          || test_ctx->handshake_mode
                              == tls_TEST_HANDSHAKE_KEY_UPDATE_CLIENT
                          || test_ctx->handshake_mode
                              == tls_TEST_HANDSHAKE_POST_HANDSHAKE_AUTH)) {
        peer->status = PEER_TEST_FAILURE;
        return;
    }

    /* Reset the count of the amount of app data we need to read/write */
    peer->bytes_to_write = peer->bytes_to_read = test_ctx->app_data_size;

    /* Check if we are the peer that is going to initiate */
    if ((test_ctx->handshake_mode == tls_TEST_HANDSHAKE_RENEG_SERVER
                && tls_is_server(peer->tls))
            || (test_ctx->handshake_mode == tls_TEST_HANDSHAKE_RENEG_CLIENT
                && !tls_is_server(peer->tls))) {
        /*
         * If we already asked for a renegotiation then fall through to the
         * tls_read() below.
         */
        if (!tls_renegotiate_pending(peer->tls)) {
            /*
             * If we are the client we will always attempt to resume the
             * session. The server may or may not resume dependent on the
             * setting of tls_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
             */
            if (tls_is_server(peer->tls)) {
                ret = tls_renegotiate(peer->tls);
            } else {
                if (test_ctx->extra.client.reneg_ciphers != NULL) {
                    if (!tls_set_cipher_list(peer->tls,
                                test_ctx->extra.client.reneg_ciphers)) {
                        peer->status = PEER_ERROR;
                        return;
                    }
                    ret = tls_renegotiate(peer->tls);
                } else {
                    ret = tls_renegotiate_abbreviated(peer->tls);
                }
            }
            if (!ret) {
                peer->status = PEER_ERROR;
                return;
            }
            do_handshake_step(peer);
            /*
             * If status is PEER_RETRY it means we're waiting on the peer to
             * continue the handshake. As far as setting up the renegotiation is
             * concerned that is a success. The next step will continue the
             * handshake to its conclusion.
             *
             * If status is PEER_SUCCESS then we are the server and we have
             * successfully sent the HelloRequest. We need to continue to wait
             * until the handshake arrives from the client.
             */
            if (peer->status == PEER_RETRY)
                peer->status = PEER_SUCCESS;
            else if (peer->status == PEER_SUCCESS)
                peer->status = PEER_RETRY;
            return;
        }
    } else if (test_ctx->handshake_mode == tls_TEST_HANDSHAKE_KEY_UPDATE_SERVER
               || test_ctx->handshake_mode
                  == tls_TEST_HANDSHAKE_KEY_UPDATE_CLIENT) {
        if (tls_is_server(peer->tls)
                != (test_ctx->handshake_mode
                    == tls_TEST_HANDSHAKE_KEY_UPDATE_SERVER)) {
            peer->status = PEER_SUCCESS;
            return;
        }

        ret = tls_key_update(peer->tls, test_ctx->key_update_type);
        if (!ret) {
            peer->status = PEER_ERROR;
            return;
        }
        do_handshake_step(peer);
        /*
         * This is a one step handshake. We shouldn't get anything other than
         * PEER_SUCCESS
         */
        if (peer->status != PEER_SUCCESS)
            peer->status = PEER_ERROR;
        return;
    } else if (test_ctx->handshake_mode == tls_TEST_HANDSHAKE_POST_HANDSHAKE_AUTH) {
        if (tls_is_server(peer->tls)) {
            /* Make the server believe it's received the extension */
            if (test_ctx->extra.server.force_pha)
                peer->tls->post_handshake_auth = tls_PHA_EXT_RECEIVED;
            ret = tls_verify_client_post_handshake(peer->tls);
            if (!ret) {
                peer->status = PEER_ERROR;
                return;
            }
        }
        do_handshake_step(peer);
        /*
         * This is a one step handshake. We shouldn't get anything other than
         * PEER_SUCCESS
         */
        if (peer->status != PEER_SUCCESS)
            peer->status = PEER_ERROR;
        return;
    }

    /*
     * The tls object is still expecting app data, even though it's going to
     * get a handshake message. We try to read, and it should fail - after which
     * we should be in a handshake
     */
    ret = tls_read(peer->tls, &buf, sizeof(buf));
    if (ret >= 0) {
        /*
         * We're not actually expecting data - we're expecting a reneg to
         * start
         */
        peer->status = PEER_ERROR;
        return;
    } else {
        int error = tls_get_error(peer->tls, ret);
        if (error != tls_ERROR_WANT_READ) {
            peer->status = PEER_ERROR;
            return;
        }
        /* If we're not in init yet then we're not done with setup yet */
        if (!tls_in_init(peer->tls))
            return;
    }

    peer->status = PEER_SUCCESS;
}


/*
 * RFC 5246 says:
 *
 * Note that as of TLS 1.1,
 *     failure to properly close a connection no longer requires that a
 *     session not be resumed.  This is a change from TLS 1.0 to conform
 *     with widespread implementation practice.
 *
 * However,
 * (a) Opentls requires that a connection be shutdown for all protocol versions.
 * (b) We test lower versions, too.
 * So we just implement shutdown. We do a full bidirectional shutdown so that we
 * can compare sent and received close_notify alerts and get some test coverage
 * for tls_shutdown as a bonus.
 */
static void do_shutdown_step(PEER *peer)
{
    int ret;

    if (!TEST_int_eq(peer->status, PEER_RETRY)) {
        peer->status = PEER_TEST_FAILURE;
        return;
    }
    ret = tls_shutdown(peer->tls);

    if (ret == 1) {
        peer->status = PEER_SUCCESS;
    } else if (ret < 0) { /* On 0, we retry. */
        int error = tls_get_error(peer->tls, ret);

        if (error != tls_ERROR_WANT_READ && error != tls_ERROR_WANT_WRITE)
            peer->status = PEER_ERROR;
    }
}

typedef enum {
    HANDSHAKE,
    RENEG_APPLICATION_DATA,
    RENEG_SETUP,
    RENEG_HANDSHAKE,
    APPLICATION_DATA,
    SHUTDOWN,
    CONNECTION_DONE
} connect_phase_t;


static int renegotiate_op(const tls_TEST_CTX *test_ctx)
{
    switch (test_ctx->handshake_mode) {
    case tls_TEST_HANDSHAKE_RENEG_SERVER:
    case tls_TEST_HANDSHAKE_RENEG_CLIENT:
        return 1;
    default:
        return 0;
    }
}
static int post_handshake_op(const tls_TEST_CTX *test_ctx)
{
    switch (test_ctx->handshake_mode) {
    case tls_TEST_HANDSHAKE_KEY_UPDATE_CLIENT:
    case tls_TEST_HANDSHAKE_KEY_UPDATE_SERVER:
    case tls_TEST_HANDSHAKE_POST_HANDSHAKE_AUTH:
        return 1;
    default:
        return 0;
    }
}

static connect_phase_t next_phase(const tls_TEST_CTX *test_ctx,
                                  connect_phase_t phase)
{
    switch (phase) {
    case HANDSHAKE:
        if (renegotiate_op(test_ctx) || post_handshake_op(test_ctx))
            return RENEG_APPLICATION_DATA;
        return APPLICATION_DATA;
    case RENEG_APPLICATION_DATA:
        return RENEG_SETUP;
    case RENEG_SETUP:
        if (post_handshake_op(test_ctx))
            return APPLICATION_DATA;
        return RENEG_HANDSHAKE;
    case RENEG_HANDSHAKE:
        return APPLICATION_DATA;
    case APPLICATION_DATA:
        return SHUTDOWN;
    case SHUTDOWN:
        return CONNECTION_DONE;
    case CONNECTION_DONE:
        TEST_error("Trying to progress after connection done");
        break;
    }
    return -1;
}

static void do_connect_step(const tls_TEST_CTX *test_ctx, PEER *peer,
                            connect_phase_t phase)
{
    switch (phase) {
    case HANDSHAKE:
        do_handshake_step(peer);
        break;
    case RENEG_APPLICATION_DATA:
        do_app_data_step(peer);
        break;
    case RENEG_SETUP:
        do_reneg_setup_step(test_ctx, peer);
        break;
    case RENEG_HANDSHAKE:
        do_handshake_step(peer);
        break;
    case APPLICATION_DATA:
        do_app_data_step(peer);
        break;
    case SHUTDOWN:
        do_shutdown_step(peer);
        break;
    case CONNECTION_DONE:
        TEST_error("Action after connection done");
        break;
    }
}

typedef enum {
    /* Both parties succeeded. */
    HANDSHAKE_SUCCESS,
    /* Client errored. */
    CLIENT_ERROR,
    /* Server errored. */
    SERVER_ERROR,
    /* Peers are in inconsistent state. */
    INTERNAL_ERROR,
    /* One or both peers not done. */
    HANDSHAKE_RETRY
} handshake_status_t;

/*
 * Determine the handshake outcome.
 * last_status: the status of the peer to have acted last.
 * previous_status: the status of the peer that didn't act last.
 * client_spoke_last: 1 if the client went last.
 */
static handshake_status_t handshake_status(peer_status_t last_status,
                                           peer_status_t previous_status,
                                           int client_spoke_last)
{
    switch (last_status) {
    case PEER_TEST_FAILURE:
        return INTERNAL_ERROR;

    case PEER_WAITING:
        /* Shouldn't ever happen */
        return INTERNAL_ERROR;

    case PEER_SUCCESS:
        switch (previous_status) {
        case PEER_TEST_FAILURE:
            return INTERNAL_ERROR;
        case PEER_SUCCESS:
            /* Both succeeded. */
            return HANDSHAKE_SUCCESS;
        case PEER_WAITING:
        case PEER_RETRY:
            /* Let the first peer finish. */
            return HANDSHAKE_RETRY;
        case PEER_ERROR:
            /*
             * Second peer succeeded despite the fact that the first peer
             * already errored. This shouldn't happen.
             */
            return INTERNAL_ERROR;
        }
        break;

    case PEER_RETRY:
        return HANDSHAKE_RETRY;

    case PEER_ERROR:
        switch (previous_status) {
        case PEER_TEST_FAILURE:
            return INTERNAL_ERROR;
        case PEER_WAITING:
            /* The client failed immediately before sending the ClientHello */
            return client_spoke_last ? CLIENT_ERROR : INTERNAL_ERROR;
        case PEER_SUCCESS:
            /*
             * First peer succeeded but second peer errored.
             * TODO(emilia): we should be able to continue here (with some
             * application data?) to ensure the first peer receives the
             * alert / close_notify.
             * (No tests currently exercise this branch.)
             */
            return client_spoke_last ? CLIENT_ERROR : SERVER_ERROR;
        case PEER_RETRY:
            /* We errored; let the peer finish. */
            return HANDSHAKE_RETRY;
        case PEER_ERROR:
            /* Both peers errored. Return the one that errored first. */
            return client_spoke_last ? SERVER_ERROR : CLIENT_ERROR;
        }
    }
    /* Control should never reach here. */
    return INTERNAL_ERROR;
}

/* Convert unsigned char buf's that shouldn't contain any NUL-bytes to char. */
static char *dup_str(const unsigned char *in, size_t len)
{
    char *ret = NULL;

    if (len == 0)
        return NULL;

    /* Assert that the string does not contain NUL-bytes. */
    if (TEST_size_t_eq(OPENtls_strnlen((const char*)(in), len), len))
        TEST_ptr(ret = OPENtls_strndup((const char*)(in), len));
    return ret;
}

static int pkey_type(EVP_PKEY *pkey)
{
    int nid = EVP_PKEY_id(pkey);

#ifndef OPENtls_NO_EC
    if (nid == EVP_PKEY_EC) {
        const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
        return EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
    }
#endif
    return nid;
}

static int peer_pkey_type(tls *s)
{
    X509 *x = tls_get_peer_certificate(s);

    if (x != NULL) {
        int nid = pkey_type(X509_get0_pubkey(x));

        X509_free(x);
        return nid;
    }
    return NID_undef;
}

#if !defined(OPENtls_NO_SCTP) && !defined(OPENtls_NO_SOCK)
static int set_sock_as_sctp(int sock)
{
    struct sctp_assocparams assocparams;
    struct sctp_rtoinfo rto_info;
    BIO *tmpbio;

    /*
     * To allow tests to fail fast (within a second or so), reduce the
     * retransmission timeouts and the number of retransmissions.
     */
    memset(&rto_info, 0, sizeof(struct sctp_rtoinfo));
    rto_info.srto_initial = 100;
    rto_info.srto_max = 200;
    rto_info.srto_min = 50;
    (void)setsockopt(sock, IPPROTO_SCTP, SCTP_RTOINFO,
                     (const void *)&rto_info, sizeof(struct sctp_rtoinfo));
    memset(&assocparams, 0, sizeof(struct sctp_assocparams));
    assocparams.sasoc_asocmaxrxt = 2;
    (void)setsockopt(sock, IPPROTO_SCTP, SCTP_ASSOCINFO,
                     (const void *)&assocparams,
                     sizeof(struct sctp_assocparams));

    /*
     * For SCTP we have to set various options on the socket prior to
     * connecting. This is done automatically by BIO_new_dgram_sctp().
     * We don't actually need the created BIO though so we free it again
     * immediately.
     */
    tmpbio = BIO_new_dgram_sctp(sock, BIO_NOCLOSE);

    if (tmpbio == NULL)
        return 0;
    BIO_free(tmpbio);

    return 1;
}

static int create_sctp_socks(int *ssock, int *csock)
{
    BIO_ADDRINFO *res = NULL;
    const BIO_ADDRINFO *ai = NULL;
    int lsock = INVALID_SOCKET, asock = INVALID_SOCKET;
    int consock = INVALID_SOCKET;
    int ret = 0;
    int family = 0;

    if (BIO_sock_init() != 1)
        return 0;

    /*
     * Port is 4463. It could be anything. It will fail if it's already being
     * used for some other SCTP service. It seems unlikely though so we don't
     * worry about it here.
     */
    if (!BIO_lookup_ex(NULL, "4463", BIO_LOOKUP_SERVER, family, SOCK_STREAM,
                       IPPROTO_SCTP, &res))
        return 0;

    for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {
        family = BIO_ADDRINFO_family(ai);
        lsock = BIO_socket(family, SOCK_STREAM, IPPROTO_SCTP, 0);
        if (lsock == INVALID_SOCKET) {
            /* Maybe the kernel doesn't support the socket family, even if
             * BIO_lookup() added it in the returned result...
             */
            continue;
        }

        if (!set_sock_as_sctp(lsock)
                || !BIO_listen(lsock, BIO_ADDRINFO_address(ai),
                               BIO_SOCK_REUSEADDR)) {
            BIO_closesocket(lsock);
            lsock = INVALID_SOCKET;
            continue;
        }

        /* Success, don't try any more addresses */
        break;
    }

    if (lsock == INVALID_SOCKET)
        goto err;

    BIO_ADDRINFO_free(res);
    res = NULL;

    if (!BIO_lookup_ex(NULL, "4463", BIO_LOOKUP_CLIENT, family, SOCK_STREAM,
                        IPPROTO_SCTP, &res))
        goto err;

    consock = BIO_socket(family, SOCK_STREAM, IPPROTO_SCTP, 0);
    if (consock == INVALID_SOCKET)
        goto err;

    if (!set_sock_as_sctp(consock)
            || !BIO_connect(consock, BIO_ADDRINFO_address(res), 0)
            || !BIO_socket_nbio(consock, 1))
        goto err;

    asock = BIO_accept_ex(lsock, NULL, BIO_SOCK_NONBLOCK);
    if (asock == INVALID_SOCKET)
        goto err;

    *csock = consock;
    *ssock = asock;
    consock = asock = INVALID_SOCKET;
    ret = 1;

 err:
    BIO_ADDRINFO_free(res);
    if (consock != INVALID_SOCKET)
        BIO_closesocket(consock);
    if (lsock != INVALID_SOCKET)
        BIO_closesocket(lsock);
    if (asock != INVALID_SOCKET)
        BIO_closesocket(asock);
    return ret;
}
#endif

/*
 * Note that |extra| points to the correct client/server configuration
 * within |test_ctx|. When configuring the handshake, general mode settings
 * are taken from |test_ctx|, and client/server-specific settings should be
 * taken from |extra|.
 *
 * The configuration code should never reach into |test_ctx->extra| or
 * |test_ctx->resume_extra| directly.
 *
 * (We could refactor test mode settings into a substructure. This would result
 * in cleaner argument passing but would complicate the test configuration
 * parsing.)
 */
static HANDSHAKE_RESULT *do_handshake_internal(
    tls_CTX *server_ctx, tls_CTX *server2_ctx, tls_CTX *client_ctx,
    const tls_TEST_CTX *test_ctx, const tls_TEST_EXTRA_CONF *extra,
    tls_SESSION *session_in, tls_SESSION *serv_sess_in,
    tls_SESSION **session_out, tls_SESSION **serv_sess_out)
{
    PEER server, client;
    BIO *client_to_server = NULL, *server_to_client = NULL;
    HANDSHAKE_EX_DATA server_ex_data, client_ex_data;
    CTX_DATA client_ctx_data, server_ctx_data, server2_ctx_data;
    HANDSHAKE_RESULT *ret = HANDSHAKE_RESULT_new();
    int client_turn = 1, client_turn_count = 0, client_wait_count = 0;
    connect_phase_t phase = HANDSHAKE;
    handshake_status_t status = HANDSHAKE_RETRY;
    const unsigned char* tick = NULL;
    size_t tick_len = 0;
    const unsigned char* sess_id = NULL;
    unsigned int sess_id_len = 0;
    tls_SESSION* sess = NULL;
    const unsigned char *proto = NULL;
    /* API dictates unsigned int rather than size_t. */
    unsigned int proto_len = 0;
    EVP_PKEY *tmp_key;
    const STACK_OF(X509_NAME) *names;
    time_t start;
    const char* cipher;

    if (ret == NULL)
        return NULL;

    memset(&server_ctx_data, 0, sizeof(server_ctx_data));
    memset(&server2_ctx_data, 0, sizeof(server2_ctx_data));
    memset(&client_ctx_data, 0, sizeof(client_ctx_data));
    memset(&server, 0, sizeof(server));
    memset(&client, 0, sizeof(client));
    memset(&server_ex_data, 0, sizeof(server_ex_data));
    memset(&client_ex_data, 0, sizeof(client_ex_data));

    if (!configure_handshake_ctx(server_ctx, server2_ctx, client_ctx,
                                 test_ctx, extra, &server_ctx_data,
                                 &server2_ctx_data, &client_ctx_data)) {
        TEST_note("configure_handshake_ctx");
        return NULL;
    }

#if !defined(OPENtls_NO_SCTP) && !defined(OPENtls_NO_SOCK)
    if (test_ctx->enable_client_sctp_label_bug)
        tls_CTX_set_mode(client_ctx, tls_MODE_DTLS_SCTP_LABEL_LENGTH_BUG);
    if (test_ctx->enable_server_sctp_label_bug)
        tls_CTX_set_mode(server_ctx, tls_MODE_DTLS_SCTP_LABEL_LENGTH_BUG);
#endif

    /* Setup tls and buffers; additional configuration happens below. */
    if (!create_peer(&server, server_ctx)) {
        TEST_note("creating server context");
        goto err;
    }
    if (!create_peer(&client, client_ctx)) {
        TEST_note("creating client context");
        goto err;
    }

    server.bytes_to_write = client.bytes_to_read = test_ctx->app_data_size;
    client.bytes_to_write = server.bytes_to_read = test_ctx->app_data_size;

    configure_handshake_tls(server.tls, client.tls, extra);
    if (session_in != NULL) {
        tls_SESSION_get_id(serv_sess_in, &sess_id_len);
        /* In case we're testing resumption without tickets. */
        if ((sess_id_len > 0
                    && !TEST_true(tls_CTX_add_session(server_ctx,
                                                      serv_sess_in)))
                || !TEST_true(tls_set_session(client.tls, session_in)))
            goto err;
        sess_id_len = 0;
    }

    ret->result = tls_TEST_INTERNAL_ERROR;

    if (test_ctx->use_sctp) {
#if !defined(OPENtls_NO_SCTP) && !defined(OPENtls_NO_SOCK)
        int csock, ssock;

        if (create_sctp_socks(&ssock, &csock)) {
            client_to_server = BIO_new_dgram_sctp(csock, BIO_CLOSE);
            server_to_client = BIO_new_dgram_sctp(ssock, BIO_CLOSE);
        }
#endif
    } else {
        client_to_server = BIO_new(BIO_s_mem());
        server_to_client = BIO_new(BIO_s_mem());
    }

    if (!TEST_ptr(client_to_server)
            || !TEST_ptr(server_to_client))
        goto err;

    /* Non-blocking bio. */
    BIO_set_nbio(client_to_server, 1);
    BIO_set_nbio(server_to_client, 1);

    tls_set_connect_state(client.tls);
    tls_set_accept_state(server.tls);

    /* The bios are now owned by the tls object. */
    if (test_ctx->use_sctp) {
        tls_set_bio(client.tls, client_to_server, client_to_server);
        tls_set_bio(server.tls, server_to_client, server_to_client);
    } else {
        tls_set_bio(client.tls, server_to_client, client_to_server);
        if (!TEST_int_gt(BIO_up_ref(server_to_client), 0)
                || !TEST_int_gt(BIO_up_ref(client_to_server), 0))
            goto err;
        tls_set_bio(server.tls, client_to_server, server_to_client);
    }

    ex_data_idx = tls_get_ex_new_index(0, "ex data", NULL, NULL, NULL);
    if (!TEST_int_ge(ex_data_idx, 0)
            || !TEST_int_eq(tls_set_ex_data(server.tls, ex_data_idx, &server_ex_data), 1)
            || !TEST_int_eq(tls_set_ex_data(client.tls, ex_data_idx, &client_ex_data), 1))
        goto err;

    tls_set_info_callback(server.tls, &info_cb);
    tls_set_info_callback(client.tls, &info_cb);

    client.status = PEER_RETRY;
    server.status = PEER_WAITING;

    start = time(NULL);

    /*
     * Half-duplex handshake loop.
     * Client and server speak to each other synchronously in the same process.
     * We use non-blocking BIOs, so whenever one peer blocks for read, it
     * returns PEER_RETRY to indicate that it's the other peer's turn to write.
     * The handshake succeeds once both peers have succeeded. If one peer
     * errors out, we also let the other peer retry (and presumably fail).
     */
    for(;;) {
        if (client_turn) {
            do_connect_step(test_ctx, &client, phase);
            status = handshake_status(client.status, server.status,
                                      1 /* client went last */);
            if (server.status == PEER_WAITING)
                server.status = PEER_RETRY;
        } else {
            do_connect_step(test_ctx, &server, phase);
            status = handshake_status(server.status, client.status,
                                      0 /* server went last */);
        }

        switch (status) {
        case HANDSHAKE_SUCCESS:
            client_turn_count = 0;
            phase = next_phase(test_ctx, phase);
            if (phase == CONNECTION_DONE) {
                ret->result = tls_TEST_SUCCESS;
                goto err;
            } else {
                client.status = server.status = PEER_RETRY;
                /*
                 * For now, client starts each phase. Since each phase is
                 * started separately, we can later control this more
                 * precisely, for example, to test client-initiated and
                 * server-initiated shutdown.
                 */
                client_turn = 1;
                break;
            }
        case CLIENT_ERROR:
            ret->result = tls_TEST_CLIENT_FAIL;
            goto err;
        case SERVER_ERROR:
            ret->result = tls_TEST_SERVER_FAIL;
            goto err;
        case INTERNAL_ERROR:
            ret->result = tls_TEST_INTERNAL_ERROR;
            goto err;
        case HANDSHAKE_RETRY:
            if (test_ctx->use_sctp) {
                if (time(NULL) - start > 3) {
                    /*
                     * We've waited for too long. Give up.
                     */
                    ret->result = tls_TEST_INTERNAL_ERROR;
                    goto err;
                }
                /*
                 * With "real" sockets we only swap to processing the peer
                 * if they are expecting to retry. Otherwise we just retry the
                 * same endpoint again.
                 */
                if ((client_turn && server.status == PEER_RETRY)
                        || (!client_turn && client.status == PEER_RETRY))
                    client_turn ^= 1;
            } else {
                if (client_turn_count++ >= 2000) {
                    /*
                     * At this point, there's been so many PEER_RETRY in a row
                     * that it's likely both sides are stuck waiting for a read.
                     * It's time to give up.
                     */
                    ret->result = tls_TEST_INTERNAL_ERROR;
                    goto err;
                }
                if (client_turn && server.status == PEER_SUCCESS) {
                    /*
                     * The server may finish before the client because the
                     * client spends some turns processing NewSessionTickets.
                     */
                    if (client_wait_count++ >= 2) {
                        ret->result = tls_TEST_INTERNAL_ERROR;
                        goto err;
                    }
                } else {
                    /* Continue. */
                    client_turn ^= 1;
                }
            }
            break;
        }
    }
 err:
    ret->server_alert_sent = server_ex_data.alert_sent;
    ret->server_num_fatal_alerts_sent = server_ex_data.num_fatal_alerts_sent;
    ret->server_alert_received = client_ex_data.alert_received;
    ret->client_alert_sent = client_ex_data.alert_sent;
    ret->client_num_fatal_alerts_sent = client_ex_data.num_fatal_alerts_sent;
    ret->client_alert_received = server_ex_data.alert_received;
    ret->server_protocol = tls_version(server.tls);
    ret->client_protocol = tls_version(client.tls);
    ret->servername = server_ex_data.servername;
    if ((sess = tls_get0_session(client.tls)) != NULL) {
        tls_SESSION_get0_ticket(sess, &tick, &tick_len);
        sess_id = tls_SESSION_get_id(sess, &sess_id_len);
    }
    if (tick == NULL || tick_len == 0)
        ret->session_ticket = tls_TEST_SESSION_TICKET_NO;
    else
        ret->session_ticket = tls_TEST_SESSION_TICKET_YES;
    ret->compression = (tls_get_current_compression(client.tls) == NULL)
                       ? tls_TEST_COMPRESSION_NO
                       : tls_TEST_COMPRESSION_YES;
    if (sess_id == NULL || sess_id_len == 0)
        ret->session_id = tls_TEST_SESSION_ID_NO;
    else
        ret->session_id = tls_TEST_SESSION_ID_YES;
    ret->session_ticket_do_not_call = server_ex_data.session_ticket_do_not_call;

#ifndef OPENtls_NO_NEXTPROTONEG
    tls_get0_next_proto_negotiated(client.tls, &proto, &proto_len);
    ret->client_npn_negotiated = dup_str(proto, proto_len);

    tls_get0_next_proto_negotiated(server.tls, &proto, &proto_len);
    ret->server_npn_negotiated = dup_str(proto, proto_len);
#endif

    tls_get0_alpn_selected(client.tls, &proto, &proto_len);
    ret->client_alpn_negotiated = dup_str(proto, proto_len);

    tls_get0_alpn_selected(server.tls, &proto, &proto_len);
    ret->server_alpn_negotiated = dup_str(proto, proto_len);

    if ((sess = tls_get0_session(server.tls)) != NULL) {
        tls_SESSION_get0_ticket_appdata(sess, (void**)&tick, &tick_len);
        ret->result_session_ticket_app_data = OPENtls_strndup((const char*)tick, tick_len);
    }

    ret->client_resumed = tls_session_reused(client.tls);
    ret->server_resumed = tls_session_reused(server.tls);

    cipher = tls_CIPHER_get_name(tls_get_current_cipher(client.tls));
    ret->cipher = dup_str((const unsigned char*)cipher, strlen(cipher));

    if (session_out != NULL)
        *session_out = tls_get1_session(client.tls);
    if (serv_sess_out != NULL) {
        tls_SESSION *tmp = tls_get_session(server.tls);

        /*
         * We create a fresh copy that is not in the server session ctx linked
         * list.
         */
        if (tmp != NULL)
            *serv_sess_out = tls_SESSION_dup(tmp);
    }

    if (tls_get_peer_tmp_key(client.tls, &tmp_key)) {
        ret->tmp_key_type = pkey_type(tmp_key);
        EVP_PKEY_free(tmp_key);
    }

    tls_get_peer_signature_nid(client.tls, &ret->server_sign_hash);
    tls_get_peer_signature_nid(server.tls, &ret->client_sign_hash);

    tls_get_peer_signature_type_nid(client.tls, &ret->server_sign_type);
    tls_get_peer_signature_type_nid(server.tls, &ret->client_sign_type);

    names = tls_get0_peer_CA_list(client.tls);
    if (names == NULL)
        ret->client_ca_names = NULL;
    else
        ret->client_ca_names = tls_dup_CA_list(names);

    names = tls_get0_peer_CA_list(server.tls);
    if (names == NULL)
        ret->server_ca_names = NULL;
    else
        ret->server_ca_names = tls_dup_CA_list(names);

    ret->server_cert_type = peer_pkey_type(client.tls);
    ret->client_cert_type = peer_pkey_type(server.tls);

    ctx_data_free_data(&server_ctx_data);
    ctx_data_free_data(&server2_ctx_data);
    ctx_data_free_data(&client_ctx_data);

    peer_free_data(&server);
    peer_free_data(&client);
    return ret;
}

HANDSHAKE_RESULT *do_handshake(tls_CTX *server_ctx, tls_CTX *server2_ctx,
                               tls_CTX *client_ctx, tls_CTX *resume_server_ctx,
                               tls_CTX *resume_client_ctx,
                               const tls_TEST_CTX *test_ctx)
{
    HANDSHAKE_RESULT *result;
    tls_SESSION *session = NULL, *serv_sess = NULL;

    result = do_handshake_internal(server_ctx, server2_ctx, client_ctx,
                                   test_ctx, &test_ctx->extra,
                                   NULL, NULL, &session, &serv_sess);
    if (result == NULL
            || test_ctx->handshake_mode != tls_TEST_HANDSHAKE_RESUME
            || result->result == tls_TEST_INTERNAL_ERROR)
        goto end;

    if (result->result != tls_TEST_SUCCESS) {
        result->result = tls_TEST_FIRST_HANDSHAKE_FAILED;
        goto end;
    }

    HANDSHAKE_RESULT_free(result);
    /* We don't support SNI on second handshake yet, so server2_ctx is NULL. */
    result = do_handshake_internal(resume_server_ctx, NULL, resume_client_ctx,
                                   test_ctx, &test_ctx->resume_extra,
                                   session, serv_sess, NULL, NULL);
 end:
    tls_SESSION_free(session);
    tls_SESSION_free(serv_sess);
    return result;
}
