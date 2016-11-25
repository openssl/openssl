/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include "../ssl_locl.h"
#include "statem_locl.h"

/*
 * Parse the server's renegotiation binding and abort if it's not right
 */
int tls_parse_server_renegotiate(SSL *s, PACKET *pkt, int *al)
{
    size_t expected_len = s->s3->previous_client_finished_len
        + s->s3->previous_server_finished_len;
    size_t ilen;
    const unsigned char *data;

    /* Check for logic errors */
    assert(expected_len == 0 || s->s3->previous_client_finished_len != 0);
    assert(expected_len == 0 || s->s3->previous_server_finished_len != 0);

    /* Parse the length byte */
    if (!PACKET_get_1_len(pkt, &ilen)) {
        SSLerr(SSL_F_TLS_PARSE_SERVER_RENEGOTIATE,
               SSL_R_RENEGOTIATION_ENCODING_ERR);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return 0;
    }

    /* Consistency check */
    if (PACKET_remaining(pkt) != ilen) {
        SSLerr(SSL_F_TLS_PARSE_SERVER_RENEGOTIATE,
               SSL_R_RENEGOTIATION_ENCODING_ERR);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return 0;
    }

    /* Check that the extension matches */
    if (ilen != expected_len) {
        SSLerr(SSL_F_TLS_PARSE_SERVER_RENEGOTIATE,
               SSL_R_RENEGOTIATION_MISMATCH);
        *al = SSL_AD_HANDSHAKE_FAILURE;
        return 0;
    }

    if (!PACKET_get_bytes(pkt, &data, s->s3->previous_client_finished_len)
        || memcmp(data, s->s3->previous_client_finished,
                  s->s3->previous_client_finished_len) != 0) {
        SSLerr(SSL_F_TLS_PARSE_SERVER_RENEGOTIATE,
               SSL_R_RENEGOTIATION_MISMATCH);
        *al = SSL_AD_HANDSHAKE_FAILURE;
        return 0;
    }

    if (!PACKET_get_bytes(pkt, &data, s->s3->previous_server_finished_len)
        || memcmp(data, s->s3->previous_server_finished,
                  s->s3->previous_server_finished_len) != 0) {
        SSLerr(SSL_F_TLS_PARSE_SERVER_RENEGOTIATE,
               SSL_R_RENEGOTIATION_MISMATCH);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return 0;
    }
    s->s3->send_connection_binding = 1;

    return 1;
}

int tls_parse_server_server_name(SSL *s, PACKET *pkt, int *al)
{
    if (s->tlsext_hostname == NULL || PACKET_remaining(pkt) > 0) {
        *al = SSL_AD_UNRECOGNIZED_NAME;
        return 0;
    }

    if (!s->hit) {
        if (s->session->tlsext_hostname != NULL) {
            *al = SSL_AD_INTERNAL_ERROR;
            return 0;
        }
        s->session->tlsext_hostname = OPENSSL_strdup(s->tlsext_hostname);
        if (s->session->tlsext_hostname == NULL) {
            *al = SSL_AD_INTERNAL_ERROR;
            return 0;
        }
    }

    return 1;
}

#ifndef OPENSSL_NO_EC
int tls_parse_server_ec_pt_formats(SSL *s, PACKET *pkt, int *al)
{
    unsigned int ecpointformatlist_length;
    PACKET ecptformatlist;

    if (!PACKET_as_length_prefixed_1(pkt, &ecptformatlist)) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }
    if (!s->hit) {
        ecpointformatlist_length = PACKET_remaining(&ecptformatlist);
        s->session->tlsext_ecpointformatlist_length = 0;

        OPENSSL_free(s->session->tlsext_ecpointformatlist);
        s->session->tlsext_ecpointformatlist =
             OPENSSL_malloc(ecpointformatlist_length);
        if (s->session->tlsext_ecpointformatlist == NULL) {
            *al = SSL_AD_INTERNAL_ERROR;
            return 0;
        }

        s->session->tlsext_ecpointformatlist_length = ecpointformatlist_length;

        if (!PACKET_copy_bytes(&ecptformatlist,
                               s->session->tlsext_ecpointformatlist,
                               ecpointformatlist_length)) {
            *al = SSL_AD_INTERNAL_ERROR;
            return 0;
        }
    }

    return 1;
}
#endif

int tls_parse_server_session_ticket(SSL *s, PACKET *pkt, int *al)
{
    if (s->tls_session_ticket_ext_cb &&
        !s->tls_session_ticket_ext_cb(s, PACKET_data(pkt),
                                      PACKET_remaining(pkt),
                                      s->tls_session_ticket_ext_cb_arg)) {
        *al = SSL_AD_INTERNAL_ERROR;
        return 0;
    }
    if (!tls_use_ticket(s) || PACKET_remaining(pkt) > 0) {
        *al = SSL_AD_UNSUPPORTED_EXTENSION;
        return 0;
    }
    s->tlsext_ticket_expected = 1;

    return 1;
}

int tls_parse_server_status_request(SSL *s, PACKET *pkt, int *al)
{
    /*
     * MUST be empty and only sent if we've requested a status
     * request message.
     */
    if (s->tlsext_status_type == -1 || PACKET_remaining(pkt) > 0) {
        *al = SSL_AD_UNSUPPORTED_EXTENSION;
        return 0;
    }
    /* Set flag to expect CertificateStatus message */
    s->tlsext_status_expected = 1;

    return 1;
}


#ifndef OPENSSL_NO_CT
int tls_parse_server_sct(SSL *s, PACKET *pkt, int *al)
{
    /*
     * Only take it if we asked for it - i.e if there is no CT validation
     * callback set, then a custom extension MAY be processing it, so we
     * need to let control continue to flow to that.
     */
    if (s->ct_validation_callback != NULL) {
        size_t size = PACKET_remaining(pkt);

        /* Simply copy it off for later processing */
        if (s->tlsext_scts != NULL) {
            OPENSSL_free(s->tlsext_scts);
            s->tlsext_scts = NULL;
        }
        s->tlsext_scts_len = size;
        if (size > 0) {
            s->tlsext_scts = OPENSSL_malloc(size);
            if (s->tlsext_scts == NULL
                    || !PACKET_copy_bytes(pkt, s->tlsext_scts, size)) {
                *al = SSL_AD_INTERNAL_ERROR;
                return 0;
            }
        }
    } else {
        if (custom_ext_parse(s, 0, TLSEXT_TYPE_signed_certificate_timestamp,
                             PACKET_data(pkt), PACKET_remaining(pkt), al) <= 0)
            return 0;
    }

    return 1;
}
#endif


#ifndef OPENSSL_NO_NEXTPROTONEG
/*
 * ssl_next_proto_validate validates a Next Protocol Negotiation block. No
 * elements of zero length are allowed and the set of elements must exactly
 * fill the length of the block. Returns 1 on success or 0 on failure.
 */
static int ssl_next_proto_validate(PACKET *pkt)
{
    PACKET tmp_protocol;

    while (PACKET_remaining(pkt)) {
        if (!PACKET_get_length_prefixed_1(pkt, &tmp_protocol)
            || PACKET_remaining(&tmp_protocol) == 0)
            return 0;
    }

    return 1;
}

int tls_parse_server_npn(SSL *s, PACKET *pkt, int *al)
{
    unsigned char *selected;
    unsigned char selected_len;
    PACKET tmppkt;

    if (s->s3->tmp.finish_md_len != 0)
        return 1;

    /* We must have requested it. */
    if (s->ctx->next_proto_select_cb == NULL) {
        *al = SSL_AD_UNSUPPORTED_EXTENSION;
        return 0;
    }
    /* The data must be valid */
    tmppkt = *pkt;
    if (!ssl_next_proto_validate(&tmppkt)) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }
    if (s->ctx->next_proto_select_cb(s, &selected, &selected_len,
                                     PACKET_data(pkt),
                                     PACKET_remaining(pkt),
                                     s->ctx->next_proto_select_cb_arg) !=
             SSL_TLSEXT_ERR_OK) {
        *al = SSL_AD_INTERNAL_ERROR;
        return 0;
    }
    /*
     * Could be non-NULL if server has sent multiple NPN extensions in
     * a single Serverhello
     */
    OPENSSL_free(s->next_proto_negotiated);
    s->next_proto_negotiated = OPENSSL_malloc(selected_len);
    if (s->next_proto_negotiated == NULL) {
        *al = SSL_AD_INTERNAL_ERROR;
        return 0;
    }

    memcpy(s->next_proto_negotiated, selected, selected_len);
    s->next_proto_negotiated_len = selected_len;
    s->s3->next_proto_neg_seen = 1;

    return 1;
}
#endif

int tls_parse_server_alpn(SSL *s, PACKET *pkt, int *al)
{
    size_t len;

    /* We must have requested it. */
    if (!s->s3->alpn_sent) {
        *al = SSL_AD_UNSUPPORTED_EXTENSION;
        return 0;
    }
    /*-
     * The extension data consists of:
     *   uint16 list_length
     *   uint8 proto_length;
     *   uint8 proto[proto_length];
     */
    if (!PACKET_get_net_2_len(pkt, &len)
        || PACKET_remaining(pkt) != len || !PACKET_get_1_len(pkt, &len)
        || PACKET_remaining(pkt) != len) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }
    OPENSSL_free(s->s3->alpn_selected);
    s->s3->alpn_selected = OPENSSL_malloc(len);
    if (s->s3->alpn_selected == NULL) {
        *al = SSL_AD_INTERNAL_ERROR;
        return 0;
    }
    if (!PACKET_copy_bytes(pkt, s->s3->alpn_selected, len)) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }
    s->s3->alpn_selected_len = len;

    return 1;
}

#ifndef OPENSSL_NO_SRTP
int tls_parse_server_use_srtp(SSL *s, PACKET *pkt, int *al)
{
    unsigned int id, ct, mki;
    int i;
    STACK_OF(SRTP_PROTECTION_PROFILE) *clnt;
    SRTP_PROTECTION_PROFILE *prof;

    if (!PACKET_get_net_2(pkt, &ct)
        || ct != 2 || !PACKET_get_net_2(pkt, &id)
        || !PACKET_get_1(pkt, &mki)
        || PACKET_remaining(pkt) != 0) {
        SSLerr(SSL_F_TLS_PARSE_SERVER_USE_SRTP,
               SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    if (mki != 0) {
        /* Must be no MKI, since we never offer one */
        SSLerr(SSL_F_TLS_PARSE_SERVER_USE_SRTP, SSL_R_BAD_SRTP_MKI_VALUE);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return 0;
    }

    clnt = SSL_get_srtp_profiles(s);

    /* Throw an error if the server gave us an unsolicited extension */
    if (clnt == NULL) {
        SSLerr(SSL_F_TLS_PARSE_SERVER_USE_SRTP, SSL_R_NO_SRTP_PROFILES);
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    /*
     * Check to see if the server gave us something we support (and
     * presumably offered)
     */
    for (i = 0; i < sk_SRTP_PROTECTION_PROFILE_num(clnt); i++) {
        prof = sk_SRTP_PROTECTION_PROFILE_value(clnt, i);

        if (prof->id == id) {
            s->srtp_profile = prof;
            *al = 0;
            return 1;
        }
    }

    SSLerr(SSL_F_TLS_PARSE_SERVER_USE_SRTP,
           SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
    *al = SSL_AD_DECODE_ERROR;
    return 0;
}
#endif

int tls_parse_server_etm(SSL *s, PACKET *pkt, int *al)
{
    /* Ignore if inappropriate ciphersuite */
    if (!(s->options & SSL_OP_NO_ENCRYPT_THEN_MAC)
            && s->s3->tmp.new_cipher->algorithm_mac != SSL_AEAD
            && s->s3->tmp.new_cipher->algorithm_enc != SSL_RC4)
        s->s3->flags |= TLS1_FLAGS_ENCRYPT_THEN_MAC;

    return 1;
}

int tls_parse_server_ems(SSL *s, PACKET *pkt, int *al)
{
    s->s3->flags |= TLS1_FLAGS_RECEIVED_EXTMS;
    if (!s->hit)
        s->session->flags |= SSL_SESS_FLAG_EXTMS;

    return 1;
}

int tls_parse_server_key_share(SSL *s, PACKET *pkt, int *al)
{
    unsigned int group_id;
    PACKET encoded_pt;
    EVP_PKEY *ckey = s->s3->tmp.pkey, *skey = NULL;

    /* Sanity check */
    if (ckey == NULL) {
        *al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_TLS_PARSE_SERVER_KEY_SHARE, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_get_net_2(pkt, &group_id)) {
        *al = SSL_AD_HANDSHAKE_FAILURE;
        SSLerr(SSL_F_TLS_PARSE_SERVER_KEY_SHARE, SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    if (group_id != s->s3->group_id) {
        /*
         * This isn't for the group that we sent in the original
         * key_share!
         */
        *al = SSL_AD_HANDSHAKE_FAILURE;
        SSLerr(SSL_F_TLS_PARSE_SERVER_KEY_SHARE, SSL_R_BAD_KEY_SHARE);
        return 0;
    }

    if (!PACKET_as_length_prefixed_2(pkt, &encoded_pt)
            || PACKET_remaining(&encoded_pt) == 0) {
        *al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_TLS_PARSE_SERVER_KEY_SHARE, SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    skey = ssl_generate_pkey(ckey);
    if (skey == NULL) {
        *al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_TLS_PARSE_SERVER_KEY_SHARE, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!EVP_PKEY_set1_tls_encodedpoint(skey, PACKET_data(&encoded_pt),
                                        PACKET_remaining(&encoded_pt))) {
        *al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_TLS_PARSE_SERVER_KEY_SHARE, SSL_R_BAD_ECPOINT);
        return 0;
    }

    if (ssl_derive(s, ckey, skey, 1) == 0) {
        *al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_TLS_PARSE_SERVER_KEY_SHARE, ERR_R_INTERNAL_ERROR);
        EVP_PKEY_free(skey);
        return 0;
    }
    EVP_PKEY_free(skey);

    return 1;
}

static int ssl_scan_serverhello_tlsext(SSL *s, PACKET *pkt, int *al)
{
    size_t num_extensions = 0;
    RAW_EXTENSION *extensions = NULL;
    PACKET extpkt;

#ifndef OPENSSL_NO_NEXTPROTONEG
    s->s3->next_proto_neg_seen = 0;
#endif
    s->tlsext_ticket_expected = 0;

    OPENSSL_free(s->s3->alpn_selected);
    s->s3->alpn_selected = NULL;

    s->s3->flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC;

    s->s3->flags &= ~TLS1_FLAGS_RECEIVED_EXTMS;

    if (!PACKET_as_length_prefixed_2(pkt, &extpkt)) {
        /* Extensions block may be completely absent in SSLv3 */
        if (s->version != SSL3_VERSION || PACKET_remaining(pkt) != 0) {
            *al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL_SCAN_SERVERHELLO_TLSEXT, SSL_R_BAD_LENGTH);
            return 0;
        }
        PACKET_null_init(&extpkt);
    }

    /*
     * TODO(TLS1.3): We give multiple contexts for now until we're ready to
     * give something more specific
     */

    if (!tls_collect_extensions(s, &extpkt, EXT_TLS1_2_SERVER_HELLO
                                            | EXT_TLS1_3_SERVER_HELLO
                                            | EXT_TLS1_3_ENCRYPTED_EXTENSIONS
                                            | EXT_TLS1_3_CERTIFICATE,
                                &extensions, &num_extensions, al))
        return 0;

    /*
     * Determine if we need to see RI. Strictly speaking if we want to avoid
     * an attack we should *always* see RI even on initial server hello
     * because the client doesn't see any renegotiation during an attack.
     * However this would mean we could not connect to any server which
     * doesn't support RI so for the immediate future tolerate RI absence
     */
    if (!(s->options & SSL_OP_LEGACY_SERVER_CONNECT)
            && !(s->options & SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)
            && tls_get_extension_by_type(extensions, num_extensions,
                                         TLSEXT_TYPE_renegotiate) == NULL) {
        *al = SSL_AD_HANDSHAKE_FAILURE;
        SSLerr(SSL_F_SSL_SCAN_SERVERHELLO_TLSEXT,
               SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
        return 0;
    }

    if (!tls_parse_all_extensions(s, EXT_TLS1_2_SERVER_HELLO
                                     | EXT_TLS1_3_SERVER_HELLO
                                     | EXT_TLS1_3_ENCRYPTED_EXTENSIONS
                                     | EXT_TLS1_3_CERTIFICATE,
                                  extensions, num_extensions, al))
        return 0;

    if (s->hit) {
        /*
         * Check extended master secret extension is consistent with
         * original session.
         */
        if (!(s->s3->flags & TLS1_FLAGS_RECEIVED_EXTMS) !=
            !(s->session->flags & SSL_SESS_FLAG_EXTMS)) {
            *al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_SSL_SCAN_SERVERHELLO_TLSEXT, SSL_R_INCONSISTENT_EXTMS);
            return 0;
        }
    }

    return 1;
}

static int ssl_check_serverhello_tlsext(SSL *s)
{
    int ret = SSL_TLSEXT_ERR_NOACK;
    int al = SSL_AD_UNRECOGNIZED_NAME;

#ifndef OPENSSL_NO_EC
    /*
     * If we are client and using an elliptic curve cryptography cipher
     * suite, then if server returns an EC point formats lists extension it
     * must contain uncompressed.
     */
    unsigned long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
    unsigned long alg_a = s->s3->tmp.new_cipher->algorithm_auth;
    if ((s->tlsext_ecpointformatlist != NULL)
        && (s->tlsext_ecpointformatlist_length > 0)
        && (s->session->tlsext_ecpointformatlist != NULL)
        && (s->session->tlsext_ecpointformatlist_length > 0)
        && ((alg_k & SSL_kECDHE) || (alg_a & SSL_aECDSA))) {
        /* we are using an ECC cipher */
        size_t i;
        unsigned char *list;
        int found_uncompressed = 0;
        list = s->session->tlsext_ecpointformatlist;
        for (i = 0; i < s->session->tlsext_ecpointformatlist_length; i++) {
            if (*(list++) == TLSEXT_ECPOINTFORMAT_uncompressed) {
                found_uncompressed = 1;
                break;
            }
        }
        if (!found_uncompressed) {
            SSLerr(SSL_F_SSL_CHECK_SERVERHELLO_TLSEXT,
                   SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST);
            return -1;
        }
    }
    ret = SSL_TLSEXT_ERR_OK;
#endif                          /* OPENSSL_NO_EC */

    if (s->ctx != NULL && s->ctx->tlsext_servername_callback != 0)
        ret =
            s->ctx->tlsext_servername_callback(s, &al,
                                               s->ctx->tlsext_servername_arg);
    else if (s->initial_ctx != NULL
             && s->initial_ctx->tlsext_servername_callback != 0)
        ret =
            s->initial_ctx->tlsext_servername_callback(s, &al,
                                                       s->
                                                       initial_ctx->tlsext_servername_arg);

    /*
     * Ensure we get sensible values passed to tlsext_status_cb in the event
     * that we don't receive a status message
     */
    OPENSSL_free(s->tlsext_ocsp_resp);
    s->tlsext_ocsp_resp = NULL;
    s->tlsext_ocsp_resplen = 0;

    switch (ret) {
    case SSL_TLSEXT_ERR_ALERT_FATAL:
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
        return -1;

    case SSL_TLSEXT_ERR_ALERT_WARNING:
        ssl3_send_alert(s, SSL3_AL_WARNING, al);
        return 1;

    case SSL_TLSEXT_ERR_NOACK:
        s->servername_done = 0;
    default:
        return 1;
    }
}

int ssl_parse_serverhello_tlsext(SSL *s, PACKET *pkt)
{
    int al = -1;
    if (s->version < SSL3_VERSION)
        return 1;
    if (ssl_scan_serverhello_tlsext(s, pkt, &al) <= 0) {
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
        return 0;
    }

    if (ssl_check_serverhello_tlsext(s) <= 0) {
        SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_TLSEXT, SSL_R_SERVERHELLO_TLSEXT);
        return 0;
    }
    return 1;
}
