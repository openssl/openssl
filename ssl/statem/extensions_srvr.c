/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ocsp.h>
#include "../ssl_locl.h"
#include "statem_locl.h"

/*
 * Parse the client's renegotiation binding and abort if it's not right
 */
int tls_parse_ctos_renegotiate(SSL *s, PACKET *pkt, X509 *x, size_t chainidx,
                               int *al)
{
    unsigned int ilen;
    const unsigned char *data;

    /* Parse the length byte */
    if (!PACKET_get_1(pkt, &ilen)
        || !PACKET_get_bytes(pkt, &data, ilen)) {
        SSLerr(SSL_F_TLS_PARSE_CTOS_RENEGOTIATE,
               SSL_R_RENEGOTIATION_ENCODING_ERR);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return 0;
    }

    /* Check that the extension matches */
    if (ilen != s->s3->previous_client_finished_len) {
        SSLerr(SSL_F_TLS_PARSE_CTOS_RENEGOTIATE,
               SSL_R_RENEGOTIATION_MISMATCH);
        *al = SSL_AD_HANDSHAKE_FAILURE;
        return 0;
    }

    if (memcmp(data, s->s3->previous_client_finished,
               s->s3->previous_client_finished_len)) {
        SSLerr(SSL_F_TLS_PARSE_CTOS_RENEGOTIATE,
               SSL_R_RENEGOTIATION_MISMATCH);
        *al = SSL_AD_HANDSHAKE_FAILURE;
        return 0;
    }

    s->s3->send_connection_binding = 1;

    return 1;
}

/*-
 * The servername extension is treated as follows:
 *
 * - Only the hostname type is supported with a maximum length of 255.
 * - The servername is rejected if too long or if it contains zeros,
 *   in which case an fatal alert is generated.
 * - The servername field is maintained together with the session cache.
 * - When a session is resumed, the servername call back invoked in order
 *   to allow the application to position itself to the right context.
 * - The servername is acknowledged if it is new for a session or when
 *   it is identical to a previously used for the same session.
 *   Applications can control the behaviour.  They can at any time
 *   set a 'desirable' servername for a new SSL object. This can be the
 *   case for example with HTTPS when a Host: header field is received and
 *   a renegotiation is requested. In this case, a possible servername
 *   presented in the new client hello is only acknowledged if it matches
 *   the value of the Host: field.
 * - Applications must  use SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
 *   if they provide for changing an explicit servername context for the
 *   session, i.e. when the session has been established with a servername
 *   extension.
 * - On session reconnect, the servername extension may be absent.
 */
int tls_parse_ctos_server_name(SSL *s, PACKET *pkt, X509 *x, size_t chainidx,
                               int *al)
{
    unsigned int servname_type;
    PACKET sni, hostname;

    if (!PACKET_as_length_prefixed_2(pkt, &sni)
        /* ServerNameList must be at least 1 byte long. */
        || PACKET_remaining(&sni) == 0) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    /*
     * Although the server_name extension was intended to be
     * extensible to new name types, RFC 4366 defined the
     * syntax inextensibly and OpenSSL 1.0.x parses it as
     * such.
     * RFC 6066 corrected the mistake but adding new name types
     * is nevertheless no longer feasible, so act as if no other
     * SNI types can exist, to simplify parsing.
     *
     * Also note that the RFC permits only one SNI value per type,
     * i.e., we can only have a single hostname.
     */
    if (!PACKET_get_1(&sni, &servname_type)
        || servname_type != TLSEXT_NAMETYPE_host_name
        || !PACKET_as_length_prefixed_2(&sni, &hostname)) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    if (!s->hit) {
        if (PACKET_remaining(&hostname) > TLSEXT_MAXLEN_host_name) {
            *al = TLS1_AD_UNRECOGNIZED_NAME;
            return 0;
        }

        if (PACKET_contains_zero_byte(&hostname)) {
            *al = TLS1_AD_UNRECOGNIZED_NAME;
            return 0;
        }

        if (!PACKET_strndup(&hostname, &s->session->ext.hostname)) {
            *al = TLS1_AD_INTERNAL_ERROR;
            return 0;
        }

        s->servername_done = 1;
    } else {
        /*
         * TODO(openssl-team): if the SNI doesn't match, we MUST
         * fall back to a full handshake.
         */
        s->servername_done = s->session->ext.hostname
            && PACKET_equal(&hostname, s->session->ext.hostname,
                            strlen(s->session->ext.hostname));
    }

    return 1;
}

#ifndef OPENSSL_NO_SRP
int tls_parse_ctos_srp(SSL *s, PACKET *pkt, X509 *x, size_t chainidx, int *al)
{
    PACKET srp_I;

    if (!PACKET_as_length_prefixed_1(pkt, &srp_I)
            || PACKET_contains_zero_byte(&srp_I)) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    /*
     * TODO(openssl-team): currently, we re-authenticate the user
     * upon resumption. Instead, we MUST ignore the login.
     */
    if (!PACKET_strndup(&srp_I, &s->srp_ctx.login)) {
        *al = TLS1_AD_INTERNAL_ERROR;
        return 0;
    }

    return 1;
}
#endif

#ifndef OPENSSL_NO_EC
int tls_parse_ctos_ec_pt_formats(SSL *s, PACKET *pkt, X509 *x, size_t chainidx,
                                 int *al)
{
    PACKET ec_point_format_list;

    if (!PACKET_as_length_prefixed_1(pkt, &ec_point_format_list)
        || PACKET_remaining(&ec_point_format_list) == 0) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    if (!s->hit) {
        if (!PACKET_memdup(&ec_point_format_list,
                           &s->session->ext.ecpointformats,
                           &s->session->ext.ecpointformats_len)) {
            *al = TLS1_AD_INTERNAL_ERROR;
            return 0;
        }
    }

    return 1;
}
#endif                          /* OPENSSL_NO_EC */

int tls_parse_ctos_session_ticket(SSL *s, PACKET *pkt, X509 *x, size_t chainidx,
                                  int *al)
{
    if (s->ext.session_ticket_cb &&
            !s->ext.session_ticket_cb(s, PACKET_data(pkt),
                                  PACKET_remaining(pkt),
                                  s->ext.session_ticket_cb_arg)) {
        *al = TLS1_AD_INTERNAL_ERROR;
        return 0;
    }

    return 1;
}

int tls_parse_ctos_sig_algs(SSL *s, PACKET *pkt, X509 *x, size_t chainidx,
                            int *al)
{
    PACKET supported_sig_algs;

    if (!PACKET_as_length_prefixed_2(pkt, &supported_sig_algs)
            || PACKET_remaining(&supported_sig_algs) == 0) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    if (!s->hit && !tls1_save_sigalgs(s, &supported_sig_algs)) {
        *al = TLS1_AD_DECODE_ERROR;
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_OCSP
int tls_parse_ctos_status_request(SSL *s, PACKET *pkt, X509 *x, size_t chainidx,
                                  int *al)
{
    PACKET responder_id_list, exts;

    /* Not defined if we get one of these in a client Certificate */
    if (x != NULL)
        return 1;

    if (!PACKET_get_1(pkt, (unsigned int *)&s->ext.status_type)) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    if (s->ext.status_type != TLSEXT_STATUSTYPE_ocsp) {
        /*
         * We don't know what to do with any other type so ignore it.
         */
        s->ext.status_type = TLSEXT_STATUSTYPE_nothing;
        return 1;
    }

    if (!PACKET_get_length_prefixed_2 (pkt, &responder_id_list)) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    /*
     * We remove any OCSP_RESPIDs from a previous handshake
     * to prevent unbounded memory growth - CVE-2016-6304
     */
    sk_OCSP_RESPID_pop_free(s->ext.ocsp.ids, OCSP_RESPID_free);
    if (PACKET_remaining(&responder_id_list) > 0) {
        s->ext.ocsp.ids = sk_OCSP_RESPID_new_null();
        if (s->ext.ocsp.ids == NULL) {
            *al = SSL_AD_INTERNAL_ERROR;
            return 0;
        }
    } else {
        s->ext.ocsp.ids = NULL;
    }

    while (PACKET_remaining(&responder_id_list) > 0) {
        OCSP_RESPID *id;
        PACKET responder_id;
        const unsigned char *id_data;

        if (!PACKET_get_length_prefixed_2(&responder_id_list, &responder_id)
                || PACKET_remaining(&responder_id) == 0) {
            *al = SSL_AD_DECODE_ERROR;
            return 0;
        }

        id_data = PACKET_data(&responder_id);
        /* TODO(size_t): Convert d2i_* to size_t */
        id = d2i_OCSP_RESPID(NULL, &id_data,
                             (int)PACKET_remaining(&responder_id));
        if (id == NULL) {
            *al = SSL_AD_DECODE_ERROR;
            return 0;
        }

        if (id_data != PACKET_end(&responder_id)) {
            OCSP_RESPID_free(id);
            *al = SSL_AD_DECODE_ERROR;
            return 0;
        }

        if (!sk_OCSP_RESPID_push(s->ext.ocsp.ids, id)) {
            OCSP_RESPID_free(id);
            *al = SSL_AD_INTERNAL_ERROR;
            return 0;
        }
    }

    /* Read in request_extensions */
    if (!PACKET_as_length_prefixed_2(pkt, &exts)) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    if (PACKET_remaining(&exts) > 0) {
        const unsigned char *ext_data = PACKET_data(&exts);

        sk_X509_EXTENSION_pop_free(s->ext.ocsp.exts,
                                   X509_EXTENSION_free);
        s->ext.ocsp.exts =
            d2i_X509_EXTENSIONS(NULL, &ext_data, (int)PACKET_remaining(&exts));
        if (s->ext.ocsp.exts == NULL || ext_data != PACKET_end(&exts)) {
            *al = SSL_AD_DECODE_ERROR;
            return 0;
        }
    }

    return 1;
}
#endif

#ifndef OPENSSL_NO_NEXTPROTONEG
int tls_parse_ctos_npn(SSL *s, PACKET *pkt, X509 *x, size_t chainidx, int *al)
{
    /*
     * We shouldn't accept this extension on a
     * renegotiation.
     *
     * s->new_session will be set on renegotiation, but we
     * probably shouldn't rely that it couldn't be set on
     * the initial renegotiation too in certain cases (when
     * there's some other reason to disallow resuming an
     * earlier session -- the current code won't be doing
     * anything like that, but this might change).
     *
     * A valid sign that there's been a previous handshake
     * in this connection is if s->s3->tmp.finish_md_len >
     * 0.  (We are talking about a check that will happen
     * in the Hello protocol round, well before a new
     * Finished message could have been computed.)
     */
    if (s->s3->tmp.finish_md_len == 0)
        s->s3->npn_seen = 1;

    return 1;
}
#endif

/*
 * Save the ALPN extension in a ClientHello.|pkt| holds the contents of the ALPN
 * extension, not including type and length. |al| is a pointer to the alert
 * value to send in the event of a failure. Returns: 1 on success, 0 on error.
 */
int tls_parse_ctos_alpn(SSL *s, PACKET *pkt, X509 *x, size_t chainidx, int *al)
{
    PACKET protocol_list, save_protocol_list, protocol;

    if (s->s3->tmp.finish_md_len != 0)
        return 1;

    if (!PACKET_as_length_prefixed_2(pkt, &protocol_list)
        || PACKET_remaining(&protocol_list) < 2) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    save_protocol_list = protocol_list;
    do {
        /* Protocol names can't be empty. */
        if (!PACKET_get_length_prefixed_1(&protocol_list, &protocol)
                || PACKET_remaining(&protocol) == 0) {
            *al = SSL_AD_DECODE_ERROR;
            return 0;
        }
    } while (PACKET_remaining(&protocol_list) != 0);

    if (!PACKET_memdup(&save_protocol_list,
                       &s->s3->alpn_proposed, &s->s3->alpn_proposed_len)) {
        *al = TLS1_AD_INTERNAL_ERROR;
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_SRTP
int tls_parse_ctos_use_srtp(SSL *s, PACKET *pkt, X509 *x, size_t chainidx,
                            int *al)
{
    STACK_OF(SRTP_PROTECTION_PROFILE) *srvr;
    unsigned int ct, mki_len, id;
    int i, srtp_pref;
    PACKET subpkt;

    /* Ignore this if we have no SRTP profiles */
    if (SSL_get_srtp_profiles(s) == NULL)
        return 1;

    /* Pull off the length of the cipher suite list  and check it is even */
    if (!PACKET_get_net_2(pkt, &ct) || (ct & 1) != 0
            || !PACKET_get_sub_packet(pkt, &subpkt, ct)) {
        SSLerr(SSL_F_TLS_PARSE_CTOS_USE_SRTP,
               SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    srvr = SSL_get_srtp_profiles(s);
    s->srtp_profile = NULL;
    /* Search all profiles for a match initially */
    srtp_pref = sk_SRTP_PROTECTION_PROFILE_num(srvr);

    while (PACKET_remaining(&subpkt)) {
        if (!PACKET_get_net_2(&subpkt, &id)) {
            SSLerr(SSL_F_TLS_PARSE_CTOS_USE_SRTP,
                   SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
            *al = SSL_AD_DECODE_ERROR;
            return 0;
        }

        /*
         * Only look for match in profiles of higher preference than
         * current match.
         * If no profiles have been have been configured then this
         * does nothing.
         */
        for (i = 0; i < srtp_pref; i++) {
            SRTP_PROTECTION_PROFILE *sprof =
                sk_SRTP_PROTECTION_PROFILE_value(srvr, i);

            if (sprof->id == id) {
                s->srtp_profile = sprof;
                srtp_pref = i;
                break;
            }
        }
    }

    /* Now extract the MKI value as a sanity check, but discard it for now */
    if (!PACKET_get_1(pkt, &mki_len)) {
        SSLerr(SSL_F_TLS_PARSE_CTOS_USE_SRTP,
               SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    if (!PACKET_forward(pkt, mki_len)
        || PACKET_remaining(pkt)) {
        SSLerr(SSL_F_TLS_PARSE_CTOS_USE_SRTP, SSL_R_BAD_SRTP_MKI_VALUE);
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    return 1;
}
#endif

int tls_parse_ctos_etm(SSL *s, PACKET *pkt, X509 *x, size_t chainidx, int *al)
{
    if (!(s->options & SSL_OP_NO_ENCRYPT_THEN_MAC))
        s->s3->flags |= TLS1_FLAGS_ENCRYPT_THEN_MAC;

    return 1;
}

/*
 * Checks a list of |groups| to determine if the |group_id| is in it. If it is
 * and |checkallow| is 1 then additionally check if the group is allowed to be
 * used. Returns 1 if the group is in the list (and allowed if |checkallow| is
 * 1) or 0 otherwise.
 */
#ifndef OPENSSL_NO_TLS1_3
static int check_in_list(SSL *s, unsigned int group_id,
                         const unsigned char *groups, size_t num_groups,
                         int checkallow)
{
    size_t i;

    if (groups == NULL || num_groups == 0)
        return 0;

    for (i = 0; i < num_groups; i++, groups += 2) {
        unsigned int share_id = (groups[0] << 8) | (groups[1]);

        if (group_id == share_id
                && (!checkallow
                    || tls_curve_allowed(s, groups, SSL_SECOP_CURVE_CHECK))) {
            break;
        }
    }

    /* If i == num_groups then not in the list */
    return i < num_groups;
}
#endif

/*
 * Process a key_share extension received in the ClientHello. |pkt| contains
 * the raw PACKET data for the extension. Returns 1 on success or 0 on failure.
 * If a failure occurs then |*al| is set to an appropriate alert value.
 */
int tls_parse_ctos_key_share(SSL *s, PACKET *pkt, X509 *x, size_t chainidx,
                             int *al)
{
#ifndef OPENSSL_NO_TLS1_3
    unsigned int group_id;
    PACKET key_share_list, encoded_pt;
    const unsigned char *clntcurves, *srvrcurves;
    size_t clnt_num_curves, srvr_num_curves;
    int group_nid, found = 0;
    unsigned int curve_flags;

    if (s->hit)
        return 1;

    /* Sanity check */
    if (s->s3->peer_tmp != NULL) {
        *al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_TLS_PARSE_CTOS_KEY_SHARE, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_as_length_prefixed_2(pkt, &key_share_list)) {
        *al = SSL_AD_HANDSHAKE_FAILURE;
        SSLerr(SSL_F_TLS_PARSE_CTOS_KEY_SHARE, SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    /* Get our list of supported curves */
    if (!tls1_get_curvelist(s, 0, &srvrcurves, &srvr_num_curves)) {
        *al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_TLS_PARSE_CTOS_KEY_SHARE, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Get the clients list of supported curves.
     * TODO(TLS1.3): We should validate that we actually received
     * supported_groups!
     */
    if (!tls1_get_curvelist(s, 1, &clntcurves, &clnt_num_curves)) {
        *al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_TLS_PARSE_CTOS_KEY_SHARE, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    while (PACKET_remaining(&key_share_list) > 0) {
        if (!PACKET_get_net_2(&key_share_list, &group_id)
                || !PACKET_get_length_prefixed_2(&key_share_list, &encoded_pt)
                || PACKET_remaining(&encoded_pt) == 0) {
            *al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_TLS_PARSE_CTOS_KEY_SHARE,
                   SSL_R_LENGTH_MISMATCH);
            return 0;
        }

        /*
         * If we already found a suitable key_share we loop through the
         * rest to verify the structure, but don't process them.
         */
        if (found)
            continue;

        /* Check if this share is in supported_groups sent from client */
        if (!check_in_list(s, group_id, clntcurves, clnt_num_curves, 0)) {
            *al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_TLS_PARSE_CTOS_KEY_SHARE, SSL_R_BAD_KEY_SHARE);
            return 0;
        }

        /* Check if this share is for a group we can use */
        if (!check_in_list(s, group_id, srvrcurves, srvr_num_curves, 1)) {
            /* Share not suitable */
            continue;
        }

        group_nid = tls1_ec_curve_id2nid(group_id, &curve_flags);

        if (group_nid == 0) {
            *al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_TLS_PARSE_CTOS_KEY_SHARE,
                   SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS);
            return 0;
        }

        if ((curve_flags & TLS_CURVE_TYPE) == TLS_CURVE_CUSTOM) {
            /* Can happen for some curves, e.g. X25519 */
            EVP_PKEY *key = EVP_PKEY_new();

            if (key == NULL || !EVP_PKEY_set_type(key, group_nid)) {
                *al = SSL_AD_INTERNAL_ERROR;
                SSLerr(SSL_F_TLS_PARSE_CTOS_KEY_SHARE, ERR_R_EVP_LIB);
                EVP_PKEY_free(key);
                return 0;
            }
            s->s3->peer_tmp = key;
        } else {
            /* Set up EVP_PKEY with named curve as parameters */
            EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

            if (pctx == NULL
                    || EVP_PKEY_paramgen_init(pctx) <= 0
                    || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                                                              group_nid) <= 0
                    || EVP_PKEY_paramgen(pctx, &s->s3->peer_tmp) <= 0) {
                *al = SSL_AD_INTERNAL_ERROR;
                SSLerr(SSL_F_TLS_PARSE_CTOS_KEY_SHARE, ERR_R_EVP_LIB);
                EVP_PKEY_CTX_free(pctx);
                return 0;
            }
            EVP_PKEY_CTX_free(pctx);
            pctx = NULL;
        }
        s->s3->group_id = group_id;

        if (!EVP_PKEY_set1_tls_encodedpoint(s->s3->peer_tmp,
                PACKET_data(&encoded_pt),
                PACKET_remaining(&encoded_pt))) {
            *al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_TLS_PARSE_CTOS_KEY_SHARE, SSL_R_BAD_ECPOINT);
            return 0;
        }

        found = 1;
    }
#endif

    return 1;
}

#ifndef OPENSSL_NO_EC
int tls_parse_ctos_supported_groups(SSL *s, PACKET *pkt, X509 *x,
                                    size_t chainidx, int *al)
{
    PACKET supported_groups_list;

    /* Each group is 2 bytes and we must have at least 1. */
    if (!PACKET_as_length_prefixed_2(pkt, &supported_groups_list)
            || PACKET_remaining(&supported_groups_list) == 0
            || (PACKET_remaining(&supported_groups_list) % 2) != 0) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    if (!s->hit
            && !PACKET_memdup(&supported_groups_list,
                              &s->session->ext.supportedgroups,
                              &s->session->ext.supportedgroups_len)) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    return 1;
}
#endif

int tls_parse_ctos_ems(SSL *s, PACKET *pkt, X509 *x, size_t chainidx, int *al)
{
    /* The extension must always be empty */
    if (PACKET_remaining(pkt) != 0) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    s->s3->flags |= TLS1_FLAGS_RECEIVED_EXTMS;

    return 1;
}

/*
 * Add the server's renegotiation binding
 */
int tls_construct_stoc_renegotiate(SSL *s, WPACKET *pkt, X509 *x, size_t
                                   chainidx, int *al)
{
    if (!s->s3->send_connection_binding)
        return 1;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_renegotiate)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_start_sub_packet_u8(pkt)
            || !WPACKET_memcpy(pkt, s->s3->previous_client_finished,
                               s->s3->previous_client_finished_len)
            || !WPACKET_memcpy(pkt, s->s3->previous_server_finished,
                               s->s3->previous_server_finished_len)
            || !WPACKET_close(pkt)
            || !WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_STOC_RENEGOTIATE, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

int tls_construct_stoc_server_name(SSL *s, WPACKET *pkt, X509 *x,
                                   size_t chainidx, int *al)
{
    if (s->hit || s->servername_done != 1
            || s->session->ext.hostname == NULL)
        return 1;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_server_name)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_STOC_SERVER_NAME, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_EC
int tls_construct_stoc_ec_pt_formats(SSL *s, WPACKET *pkt, X509 *x,
                                     size_t chainidx, int *al)
{
    unsigned long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
    unsigned long alg_a = s->s3->tmp.new_cipher->algorithm_auth;
    int using_ecc = ((alg_k & SSL_kECDHE) || (alg_a & SSL_aECDSA))
                    && (s->session->ext.ecpointformats != NULL);
    const unsigned char *plist;
    size_t plistlen;

    if (!using_ecc)
        return 1;

    tls1_get_formatlist(s, &plist, &plistlen);
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_ec_point_formats)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_sub_memcpy_u8(pkt, plist, plistlen)
            || !WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_STOC_EC_PT_FORMATS, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}
#endif

int tls_construct_stoc_session_ticket(SSL *s, WPACKET *pkt, X509 *x,
                                      size_t chainidx, int *al)
{
    if (!s->ext.ticket_expected || !tls_use_ticket(s)) {
        s->ext.ticket_expected = 0;
        return 1;
    }

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_session_ticket)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_STOC_SESSION_TICKET, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_OCSP
int tls_construct_stoc_status_request(SSL *s, WPACKET *pkt, X509 *x,
                                     size_t chainidx, int *al)
{
    if (!s->ext.status_expected)
        return 1;

    if (SSL_IS_TLS13(s) && chainidx != 0)
        return 1;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_status_request)
            || !WPACKET_start_sub_packet_u16(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_STOC_STATUS_REQUEST, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * In TLSv1.3 we include the certificate status itself. In <= TLSv1.2 we
     * send back an empty extension, with the certificate status appearing as a
     * separate message
     */
    if ((SSL_IS_TLS13(s) && !tls_construct_cert_status_body(s, pkt))
            || !WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_STOC_STATUS_REQUEST, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}
#endif

#ifndef OPENSSL_NO_NEXTPROTONEG
int tls_construct_stoc_next_proto_neg(SSL *s, WPACKET *pkt, X509 *x,
                                      size_t chainidx, int *al)
{
    const unsigned char *npa;
    unsigned int npalen;
    int ret;
    int npn_seen = s->s3->npn_seen;

    s->s3->npn_seen = 0;
    if (!npn_seen || s->ctx->ext.npn_advertised_cb == NULL)
        return 1;

    ret = s->ctx->ext.npn_advertised_cb(s, &npa, &npalen,
                                        s->ctx->ext.npn_advertised_cb_arg);
    if (ret == SSL_TLSEXT_ERR_OK) {
        if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_next_proto_neg)
                || !WPACKET_sub_memcpy_u16(pkt, npa, npalen)) {
            SSLerr(SSL_F_TLS_CONSTRUCT_STOC_NEXT_PROTO_NEG,
                   ERR_R_INTERNAL_ERROR);
            return 0;
        }
        s->s3->npn_seen = 1;
    }

    return 1;
}
#endif

int tls_construct_stoc_alpn(SSL *s, WPACKET *pkt, X509 *x, size_t chainidx,
                            int *al)
{
    if (s->s3->alpn_selected == NULL)
        return 1;

    if (!WPACKET_put_bytes_u16(pkt,
                TLSEXT_TYPE_application_layer_protocol_negotiation)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_sub_memcpy_u8(pkt, s->s3->alpn_selected,
                                      s->s3->alpn_selected_len)
            || !WPACKET_close(pkt)
            || !WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_STOC_ALPN, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_SRTP
int tls_construct_stoc_use_srtp(SSL *s, WPACKET *pkt, X509 *x, size_t chainidx,
                                int *al)
{
    if (s->srtp_profile == NULL)
        return 1;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_use_srtp)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u16(pkt, 2)
            || !WPACKET_put_bytes_u16(pkt, s->srtp_profile->id)
            || !WPACKET_put_bytes_u8(pkt, 0)
            || !WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_STOC_USE_SRTP, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}
#endif

int tls_construct_stoc_etm(SSL *s, WPACKET *pkt, X509 *x, size_t chainidx,
                           int *al)
{
    if ((s->s3->flags & TLS1_FLAGS_ENCRYPT_THEN_MAC) == 0)
        return 1;

    /*
     * Don't use encrypt_then_mac if AEAD or RC4 might want to disable
     * for other cases too.
     */
    if (s->s3->tmp.new_cipher->algorithm_mac == SSL_AEAD
        || s->s3->tmp.new_cipher->algorithm_enc == SSL_RC4
        || s->s3->tmp.new_cipher->algorithm_enc == SSL_eGOST2814789CNT
        || s->s3->tmp.new_cipher->algorithm_enc == SSL_eGOST2814789CNT12) {
        s->s3->flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC;
        return 1;
    }

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_encrypt_then_mac)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_STOC_ETM, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

int tls_construct_stoc_ems(SSL *s, WPACKET *pkt, X509 *x, size_t chainidx,
                           int *al)
{
    if ((s->s3->flags & TLS1_FLAGS_RECEIVED_EXTMS) == 0)
        return 1;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_extended_master_secret)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_STOC_EMS, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

int tls_construct_stoc_key_share(SSL *s, WPACKET *pkt, X509 *x, size_t chainidx,
                                 int *al)
{
#ifndef OPENSSL_NO_TLS1_3
    unsigned char *encodedPoint;
    size_t encoded_pt_len = 0;
    EVP_PKEY *ckey = s->s3->peer_tmp, *skey = NULL;

    if (s->hit)
        return 1;

    if (ckey == NULL) {
        SSLerr(SSL_F_TLS_CONSTRUCT_STOC_KEY_SHARE, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_key_share)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u16(pkt, s->s3->group_id)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_STOC_KEY_SHARE, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    skey = ssl_generate_pkey(ckey);
    if (skey == NULL) {
        SSLerr(SSL_F_TLS_CONSTRUCT_STOC_KEY_SHARE, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /* Generate encoding of server key */
    encoded_pt_len = EVP_PKEY_get1_tls_encodedpoint(skey, &encodedPoint);
    if (encoded_pt_len == 0) {
        SSLerr(SSL_F_TLS_CONSTRUCT_STOC_KEY_SHARE, ERR_R_EC_LIB);
        EVP_PKEY_free(skey);
        return 0;
    }

    if (!WPACKET_sub_memcpy_u16(pkt, encodedPoint, encoded_pt_len)
            || !WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_STOC_KEY_SHARE, ERR_R_INTERNAL_ERROR);
        EVP_PKEY_free(skey);
        OPENSSL_free(encodedPoint);
        return 0;
    }
    OPENSSL_free(encodedPoint);

    /* This causes the crypto state to be updated based on the derived keys */
    s->s3->tmp.pkey = skey;
    if (ssl_derive(s, skey, ckey, 1) == 0) {
        SSLerr(SSL_F_TLS_CONSTRUCT_STOC_KEY_SHARE, ERR_R_INTERNAL_ERROR);
        return 0;
    }
#endif

    return 1;
}

int tls_construct_stoc_cryptopro_bug(SSL *s, WPACKET *pkt, X509 *x,
                                     size_t chainidx, int *al)
{
    const unsigned char cryptopro_ext[36] = {
        0xfd, 0xe8,         /* 65000 */
        0x00, 0x20,         /* 32 bytes length */
        0x30, 0x1e, 0x30, 0x08, 0x06, 0x06, 0x2a, 0x85,
        0x03, 0x02, 0x02, 0x09, 0x30, 0x08, 0x06, 0x06,
        0x2a, 0x85, 0x03, 0x02, 0x02, 0x16, 0x30, 0x08,
        0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x17
    };

    if (((s->s3->tmp.new_cipher->id & 0xFFFF) != 0x80
         && (s->s3->tmp.new_cipher->id & 0xFFFF) != 0x81)
            || (SSL_get_options(s) & SSL_OP_CRYPTOPRO_TLSEXT_BUG) == 0)
        return 1;

    if (!WPACKET_memcpy(pkt, cryptopro_ext, sizeof(cryptopro_ext))) {
        SSLerr(SSL_F_TLS_CONSTRUCT_STOC_CRYPTOPRO_BUG, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}
