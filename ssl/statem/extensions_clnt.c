/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <openssl/ocsp.h>
#include "../ssl_locl.h"
#include "statem_locl.h"

int tls_construct_ctos_renegotiate(SSL *s, WPACKET *pkt, X509 *x,
                                   size_t chainidx, int *al)
{
    /* Add RI if renegotiating */
    if (!s->renegotiate)
        return 1;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_renegotiate)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_sub_memcpy_u8(pkt, s->s3->previous_client_finished,
                               s->s3->previous_client_finished_len)
            || !WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_RENEGOTIATE, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

int tls_construct_ctos_server_name(SSL *s, WPACKET *pkt, X509 *x,
                                   size_t chainidx, int *al)
{
    if (s->ext.hostname == NULL)
        return 1;

    /* Add TLS extension servername to the Client Hello message */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_server_name)
               /* Sub-packet for server_name extension */
            || !WPACKET_start_sub_packet_u16(pkt)
               /* Sub-packet for servername list (always 1 hostname)*/
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u8(pkt, TLSEXT_NAMETYPE_host_name)
            || !WPACKET_sub_memcpy_u16(pkt, s->ext.hostname,
                                       strlen(s->ext.hostname))
            || !WPACKET_close(pkt)
            || !WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_SERVER_NAME, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_SRP
int tls_construct_ctos_srp(SSL *s, WPACKET *pkt, X509 *x, size_t chainidx,
                           int *al)
{
    /* Add SRP username if there is one */
    if (s->srp_ctx.login == NULL)
        return 1;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_srp)
               /* Sub-packet for SRP extension */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_start_sub_packet_u8(pkt)
               /* login must not be zero...internal error if so */
            || !WPACKET_set_flags(pkt, WPACKET_FLAGS_NON_ZERO_LENGTH)
            || !WPACKET_memcpy(pkt, s->srp_ctx.login,
                               strlen(s->srp_ctx.login))
            || !WPACKET_close(pkt)
            || !WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_SRP, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}
#endif

#ifndef OPENSSL_NO_EC
static int use_ecc(SSL *s)
{
    int i, end;
    unsigned long alg_k, alg_a;
    STACK_OF(SSL_CIPHER) *cipher_stack = NULL;

    /* See if we support any ECC ciphersuites */
    if (s->version == SSL3_VERSION)
        return 0;

    cipher_stack = SSL_get_ciphers(s);
    end = sk_SSL_CIPHER_num(cipher_stack);
    for (i = 0; i < end; i++) {
        const SSL_CIPHER *c = sk_SSL_CIPHER_value(cipher_stack, i);

        alg_k = c->algorithm_mkey;
        alg_a = c->algorithm_auth;
        if ((alg_k & (SSL_kECDHE | SSL_kECDHEPSK))
                || (alg_a & SSL_aECDSA)
                || c->min_tls >= TLS1_3_VERSION)
            break;
    }

    return i < end;
}

int tls_construct_ctos_ec_pt_formats(SSL *s, WPACKET *pkt, X509 *x,
                                     size_t chainidx, int *al)
{
    const unsigned char *pformats;
    size_t num_formats;

    if (!use_ecc(s))
        return 1;

    /* Add TLS extension ECPointFormats to the ClientHello message */
    tls1_get_formatlist(s, &pformats, &num_formats);

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_ec_point_formats)
               /* Sub-packet for formats extension */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_sub_memcpy_u8(pkt, pformats, num_formats)
            || !WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_EC_PT_FORMATS, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

int tls_construct_ctos_supported_groups(SSL *s, WPACKET *pkt, X509 *x,
                                        size_t chainidx, int *al)
{
    const unsigned char *pcurves = NULL, *pcurvestmp;
    size_t num_curves = 0, i;

    if (!use_ecc(s))
        return 1;

    /*
     * Add TLS extension supported_groups to the ClientHello message
     */
    /* TODO(TLS1.3): Add support for DHE groups */
    pcurves = s->ext.supportedgroups;
    if (!tls1_get_curvelist(s, 0, &pcurves, &num_curves)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_SUPPORTED_GROUPS,
               ERR_R_INTERNAL_ERROR);
        return 0;
    }
    pcurvestmp = pcurves;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_supported_groups)
               /* Sub-packet for supported_groups extension */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_start_sub_packet_u16(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_SUPPORTED_GROUPS,
               ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* Copy curve ID if supported */
    for (i = 0; i < num_curves; i++, pcurvestmp += 2) {
        if (tls_curve_allowed(s, pcurves, SSL_SECOP_CURVE_SUPPORTED)) {
            if (!WPACKET_put_bytes_u8(pkt, pcurvestmp[0])
                || !WPACKET_put_bytes_u8(pkt, pcurvestmp[1])) {
                    SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_SUPPORTED_GROUPS,
                           ERR_R_INTERNAL_ERROR);
                    return 0;
                }
        }
    }
    if (!WPACKET_close(pkt) || !WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_SUPPORTED_GROUPS,
               ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}
#endif

int tls_construct_ctos_session_ticket(SSL *s, WPACKET *pkt, X509 *x,
                                      size_t chainidx, int *al)
{
    size_t ticklen;

    if (!tls_use_ticket(s))
        return 1;

    if (!s->new_session && s->session != NULL
            && s->session->ext.tick != NULL) {
        ticklen = s->session->ext.ticklen;
    } else if (s->session && s->ext.session_ticket != NULL
               && s->ext.session_ticket->data != NULL) {
        ticklen = s->ext.session_ticket->length;
        s->session->ext.tick = OPENSSL_malloc(ticklen);
        if (s->session->ext.tick == NULL) {
            SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_SESSION_TICKET,
                   ERR_R_INTERNAL_ERROR);
            return 0;
        }
        memcpy(s->session->ext.tick,
               s->ext.session_ticket->data, ticklen);
        s->session->ext.ticklen = ticklen;
    } else {
        ticklen = 0;
    }

    if (ticklen == 0 && s->ext.session_ticket != NULL &&
            s->ext.session_ticket->data == NULL)
        return 1;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_session_ticket)
            || !WPACKET_sub_memcpy_u16(pkt, s->session->ext.tick, ticklen)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_SESSION_TICKET, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

int tls_construct_ctos_sig_algs(SSL *s, WPACKET *pkt, X509 *x, size_t chainidx,
                                int *al)
{
    size_t salglen;
    const unsigned int *salg;

    if (!SSL_CLIENT_USE_SIGALGS(s))
        return 1;

    salglen = tls12_get_psigalgs(s, &salg);
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_signature_algorithms)
               /* Sub-packet for sig-algs extension */
            || !WPACKET_start_sub_packet_u16(pkt)
               /* Sub-packet for the actual list */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !tls12_copy_sigalgs(s, pkt, salg, salglen)
            || !WPACKET_close(pkt)
            || !WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_SIG_ALGS, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_OCSP
int tls_construct_ctos_status_request(SSL *s, WPACKET *pkt, X509 *x,
                                      size_t chainidx, int *al)
{
    int i;

    /* This extension isn't defined for client Certificates */
    if (x != NULL)
        return 1;

    if (s->ext.status_type != TLSEXT_STATUSTYPE_ocsp)
        return 1;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_status_request)
               /* Sub-packet for status request extension */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u8(pkt, TLSEXT_STATUSTYPE_ocsp)
               /* Sub-packet for the ids */
            || !WPACKET_start_sub_packet_u16(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    for (i = 0; i < sk_OCSP_RESPID_num(s->ext.ocsp.ids); i++) {
        unsigned char *idbytes;
        OCSP_RESPID *id = sk_OCSP_RESPID_value(s->ext.ocsp.ids, i);
        int idlen = i2d_OCSP_RESPID(id, NULL);

        if (idlen <= 0
                   /* Sub-packet for an individual id */
                || !WPACKET_sub_allocate_bytes_u16(pkt, idlen, &idbytes)
                || i2d_OCSP_RESPID(id, &idbytes) != idlen) {
            SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST,
                   ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    if (!WPACKET_close(pkt)
            || !WPACKET_start_sub_packet_u16(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (s->ext.ocsp.exts) {
        unsigned char *extbytes;
        int extlen = i2d_X509_EXTENSIONS(s->ext.ocsp.exts, NULL);

        if (extlen < 0) {
            SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST,
                   ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (!WPACKET_allocate_bytes(pkt, extlen, &extbytes)
                || i2d_X509_EXTENSIONS(s->ext.ocsp.exts, &extbytes)
                   != extlen) {
            SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST,
                   ERR_R_INTERNAL_ERROR);
            return 0;
       }
    }
    if (!WPACKET_close(pkt) || !WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}
#endif

#ifndef OPENSSL_NO_NEXTPROTONEG
int tls_construct_ctos_npn(SSL *s, WPACKET *pkt, X509 *x, size_t chainidx,
                           int *al)
{
    if (s->ctx->ext.npn_select_cb == NULL || s->s3->tmp.finish_md_len != 0)
        return 1;

    /*
     * The client advertises an empty extension to indicate its support
     * for Next Protocol Negotiation
     */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_next_proto_neg)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_NPN, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}
#endif

int tls_construct_ctos_alpn(SSL *s, WPACKET *pkt, X509 *x, size_t chainidx,
                            int *al)
{
    s->s3->alpn_sent = 0;

    /*
     * finish_md_len is non-zero during a renegotiation, so
     * this avoids sending ALPN during the renegotiation
     */
    if (s->ext.alpn == NULL || s->s3->tmp.finish_md_len != 0)
        return 1;

    if (!WPACKET_put_bytes_u16(pkt,
                TLSEXT_TYPE_application_layer_protocol_negotiation)
               /* Sub-packet ALPN extension */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_sub_memcpy_u16(pkt, s->ext.alpn, s->ext.alpn_len)
            || !WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_ALPN, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    s->s3->alpn_sent = 1;

    return 1;
}


#ifndef OPENSSL_NO_SRTP
int tls_construct_ctos_use_srtp(SSL *s, WPACKET *pkt, X509 *x, size_t chainidx,
                                int *al)
{
    STACK_OF(SRTP_PROTECTION_PROFILE) *clnt = SSL_get_srtp_profiles(s);
    int i, end;

    if (clnt == NULL)
        return 1;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_use_srtp)
               /* Sub-packet for SRTP extension */
            || !WPACKET_start_sub_packet_u16(pkt)
               /* Sub-packet for the protection profile list */
            || !WPACKET_start_sub_packet_u16(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_USE_SRTP, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    end = sk_SRTP_PROTECTION_PROFILE_num(clnt);
    for (i = 0; i < end; i++) {
        const SRTP_PROTECTION_PROFILE *prof =
            sk_SRTP_PROTECTION_PROFILE_value(clnt, i);

        if (prof == NULL || !WPACKET_put_bytes_u16(pkt, prof->id)) {
            SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_USE_SRTP, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    if (!WPACKET_close(pkt)
               /* Add an empty use_mki value */
            || !WPACKET_put_bytes_u8(pkt, 0)
            || !WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_USE_SRTP, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}
#endif

int tls_construct_ctos_etm(SSL *s, WPACKET *pkt, X509 *x, size_t chainidx,
                           int *al)
{
    if (s->options & SSL_OP_NO_ENCRYPT_THEN_MAC)
        return 1;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_encrypt_then_mac)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_ETM, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_CT
int tls_construct_ctos_sct(SSL *s, WPACKET *pkt, X509 *x, size_t chainidx,
                           int *al)
{
    if (s->ct_validation_callback == NULL)
        return 1;

    /* Not defined for client Certificates */
    if (x != NULL)
        return 1;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_signed_certificate_timestamp)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_SCT, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}
#endif

int tls_construct_ctos_ems(SSL *s, WPACKET *pkt, X509 *x, size_t chainidx,
                           int *al)
{
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_extended_master_secret)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_EMS, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

int tls_construct_ctos_supported_versions(SSL *s, WPACKET *pkt, X509 *x,
                                          size_t chainidx, int *al)
{
    int currv, min_version, max_version, reason;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_supported_versions)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_start_sub_packet_u8(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_SUPPORTED_VERSIONS,
               ERR_R_INTERNAL_ERROR);
        return 0;
    }

    reason = ssl_get_client_min_max_version(s, &min_version, &max_version);
    if (reason != 0) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_SUPPORTED_VERSIONS, reason);
        return 0;
    }

    /*
     * TODO(TLS1.3): There is some discussion on the TLS list as to wheter
     * we should include versions <TLS1.2. For the moment we do. To be
     * reviewed later.
     */
    for (currv = max_version; currv >= min_version; currv--) {
        /* TODO(TLS1.3): Remove this first if clause prior to release!! */
        if (currv == TLS1_3_VERSION) {
            if (!WPACKET_put_bytes_u16(pkt, TLS1_3_VERSION_DRAFT)) {
                SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_SUPPORTED_VERSIONS,
                       ERR_R_INTERNAL_ERROR);
                return 0;
            }
        } else if (!WPACKET_put_bytes_u16(pkt, currv)) {
            SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_SUPPORTED_VERSIONS,
                   ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    if (!WPACKET_close(pkt) || !WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_SUPPORTED_VERSIONS,
               ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

int tls_construct_ctos_key_share(SSL *s, WPACKET *pkt, X509 *x, size_t chainidx,
                                 int *al)
{
#ifndef OPENSSL_NO_TLS1_3
    size_t i, sharessent = 0, num_curves = 0;
    const unsigned char *pcurves = NULL;

    /* key_share extension */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_key_share)
               /* Extension data sub-packet */
            || !WPACKET_start_sub_packet_u16(pkt)
               /* KeyShare list sub-packet */
            || !WPACKET_start_sub_packet_u16(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_KEY_SHARE, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    pcurves = s->ext.supportedgroups;
    if (!tls1_get_curvelist(s, 0, &pcurves, &num_curves)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_KEY_SHARE, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * TODO(TLS1.3): Make the number of key_shares sent configurable. For
     * now, just send one
     */
    for (i = 0; i < num_curves && sharessent < 1; i++, pcurves += 2) {
        unsigned char *encodedPoint = NULL;
        unsigned int curve_id = 0;
        EVP_PKEY *key_share_key = NULL;
        size_t encodedlen;

        if (!tls_curve_allowed(s, pcurves, SSL_SECOP_CURVE_SUPPORTED))
            continue;

        if (s->s3->tmp.pkey != NULL) {
            /* Shouldn't happen! */
            SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_KEY_SHARE, ERR_R_INTERNAL_ERROR);
            return 0;
        }

        /* Generate a key for this key_share */
        curve_id = (pcurves[0] << 8) | pcurves[1];
        key_share_key = ssl_generate_pkey_curve(curve_id);
        if (key_share_key == NULL) {
            SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_KEY_SHARE, ERR_R_EVP_LIB);
            return 0;
        }

        /* Encode the public key. */
        encodedlen = EVP_PKEY_get1_tls_encodedpoint(key_share_key,
                                                    &encodedPoint);
        if (encodedlen == 0) {
            SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_KEY_SHARE, ERR_R_EC_LIB);
            EVP_PKEY_free(key_share_key);
            return 0;
        }

        /* Create KeyShareEntry */
        if (!WPACKET_put_bytes_u16(pkt, curve_id)
                || !WPACKET_sub_memcpy_u16(pkt, encodedPoint, encodedlen)) {
            SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_KEY_SHARE, ERR_R_INTERNAL_ERROR);
            EVP_PKEY_free(key_share_key);
            OPENSSL_free(encodedPoint);
            return 0;
        }

        /*
         * TODO(TLS1.3): When changing to send more than one key_share we're
         * going to need to be able to save more than one EVP_PKEY. For now
         * we reuse the existing tmp.pkey
         */
        s->s3->group_id = curve_id;
        s->s3->tmp.pkey = key_share_key;
        sharessent++;
        OPENSSL_free(encodedPoint);
    }

    if (!WPACKET_close(pkt) || !WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_KEY_SHARE, ERR_R_INTERNAL_ERROR);
        return 0;
    }
#endif

    return 1;
}

#define F5_WORKAROUND_MIN_MSG_LEN   0xff
#define F5_WORKAROUND_MAX_MSG_LEN   0x200

int tls_construct_ctos_padding(SSL *s, WPACKET *pkt, X509 *x, size_t chainidx,
                               int *al)
{
    unsigned char *padbytes;
    size_t hlen;

    if ((s->options & SSL_OP_TLSEXT_PADDING) == 0)
        return 1;

    /*
     * Add padding to workaround bugs in F5 terminators. See
     * https://tools.ietf.org/html/draft-agl-tls-padding-03 NB: because this
     * code calculates the length of all existing extensions it MUST always
     * appear last.
     */
    if (!WPACKET_get_total_written(pkt, &hlen)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_PADDING, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (hlen > F5_WORKAROUND_MIN_MSG_LEN && hlen < F5_WORKAROUND_MAX_MSG_LEN) {
        /* Calculate the amond of padding we need to add */
        hlen = F5_WORKAROUND_MAX_MSG_LEN - hlen;

        /*
         * Take off the size of extension header itself (2 bytes for type and
         * 2 bytes for length bytes)
         */
        if (hlen >= 4)
            hlen -= 4;
        else
            hlen = 0;

        if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_padding)
                || !WPACKET_sub_allocate_bytes_u16(pkt, hlen, &padbytes)) {
            SSLerr(SSL_F_TLS_CONSTRUCT_CTOS_PADDING, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        memset(padbytes, 0, hlen);
    }

    return 1;
}

/*
 * Parse the server's renegotiation binding and abort if it's not right
 */
int tls_parse_stoc_renegotiate(SSL *s, PACKET *pkt, X509 *x, size_t chainidx,
                               int *al)
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
        SSLerr(SSL_F_TLS_PARSE_STOC_RENEGOTIATE,
               SSL_R_RENEGOTIATION_ENCODING_ERR);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return 0;
    }

    /* Consistency check */
    if (PACKET_remaining(pkt) != ilen) {
        SSLerr(SSL_F_TLS_PARSE_STOC_RENEGOTIATE,
               SSL_R_RENEGOTIATION_ENCODING_ERR);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return 0;
    }

    /* Check that the extension matches */
    if (ilen != expected_len) {
        SSLerr(SSL_F_TLS_PARSE_STOC_RENEGOTIATE,
               SSL_R_RENEGOTIATION_MISMATCH);
        *al = SSL_AD_HANDSHAKE_FAILURE;
        return 0;
    }

    if (!PACKET_get_bytes(pkt, &data, s->s3->previous_client_finished_len)
        || memcmp(data, s->s3->previous_client_finished,
                  s->s3->previous_client_finished_len) != 0) {
        SSLerr(SSL_F_TLS_PARSE_STOC_RENEGOTIATE,
               SSL_R_RENEGOTIATION_MISMATCH);
        *al = SSL_AD_HANDSHAKE_FAILURE;
        return 0;
    }

    if (!PACKET_get_bytes(pkt, &data, s->s3->previous_server_finished_len)
        || memcmp(data, s->s3->previous_server_finished,
                  s->s3->previous_server_finished_len) != 0) {
        SSLerr(SSL_F_TLS_PARSE_STOC_RENEGOTIATE,
               SSL_R_RENEGOTIATION_MISMATCH);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return 0;
    }
    s->s3->send_connection_binding = 1;

    return 1;
}

int tls_parse_stoc_server_name(SSL *s, PACKET *pkt, X509 *x, size_t chainidx,
                               int *al)
{
    if (s->ext.hostname == NULL || PACKET_remaining(pkt) > 0) {
        *al = SSL_AD_UNRECOGNIZED_NAME;
        return 0;
    }

    if (!s->hit) {
        if (s->session->ext.hostname != NULL) {
            *al = SSL_AD_INTERNAL_ERROR;
            return 0;
        }
        s->session->ext.hostname = OPENSSL_strdup(s->ext.hostname);
        if (s->session->ext.hostname == NULL) {
            *al = SSL_AD_INTERNAL_ERROR;
            return 0;
        }
    }

    return 1;
}

#ifndef OPENSSL_NO_EC
int tls_parse_stoc_ec_pt_formats(SSL *s, PACKET *pkt, X509 *x, size_t chainidx,
                                 int *al)
{
    unsigned int ecpointformats_len;
    PACKET ecptformatlist;

    if (!PACKET_as_length_prefixed_1(pkt, &ecptformatlist)) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }
    if (!s->hit) {
        ecpointformats_len = PACKET_remaining(&ecptformatlist);
        s->session->ext.ecpointformats_len = 0;

        OPENSSL_free(s->session->ext.ecpointformats);
        s->session->ext.ecpointformats = OPENSSL_malloc(ecpointformats_len);
        if (s->session->ext.ecpointformats == NULL) {
            *al = SSL_AD_INTERNAL_ERROR;
            return 0;
        }

        s->session->ext.ecpointformats_len = ecpointformats_len;

        if (!PACKET_copy_bytes(&ecptformatlist,
                               s->session->ext.ecpointformats,
                               ecpointformats_len)) {
            *al = SSL_AD_INTERNAL_ERROR;
            return 0;
        }
    }

    return 1;
}
#endif

int tls_parse_stoc_session_ticket(SSL *s, PACKET *pkt, X509 *x, size_t chainidx,
                                  int *al)
{
    if (s->ext.session_ticket_cb != NULL &&
        !s->ext.session_ticket_cb(s, PACKET_data(pkt),
                              PACKET_remaining(pkt),
                              s->ext.session_ticket_cb_arg)) {
        *al = SSL_AD_INTERNAL_ERROR;
        return 0;
    }

    if (!tls_use_ticket(s) || PACKET_remaining(pkt) > 0) {
        *al = SSL_AD_UNSUPPORTED_EXTENSION;
        return 0;
    }

    s->ext.ticket_expected = 1;

    return 1;
}

#ifndef OPENSSL_NO_OCSP
int tls_parse_stoc_status_request(SSL *s, PACKET *pkt, X509 *x, size_t chainidx,
                                  int *al)
{
    /*
     * MUST only be sent if we've requested a status
     * request message. In TLS <= 1.2 it must also be empty.
     */
    if (s->ext.status_type == TLSEXT_STATUSTYPE_nothing
            || (!SSL_IS_TLS13(s) && PACKET_remaining(pkt) > 0)) {
        *al = SSL_AD_UNSUPPORTED_EXTENSION;
        return 0;
    }

    if (SSL_IS_TLS13(s)) {
        /* We only know how to handle this if it's for the first Certificate in
         * the chain. We ignore any other repsonses.
         */
        if (chainidx != 0)
            return 1;
        return tls_process_cert_status_body(s, pkt, al);
    }

    /* Set flag to expect CertificateStatus message */
    s->ext.status_expected = 1;

    return 1;
}
#endif


#ifndef OPENSSL_NO_CT
int tls_parse_stoc_sct(SSL *s, PACKET *pkt, X509 *x, size_t chainidx, int *al)
{
    /*
     * Only take it if we asked for it - i.e if there is no CT validation
     * callback set, then a custom extension MAY be processing it, so we
     * need to let control continue to flow to that.
     */
    if (s->ct_validation_callback != NULL) {
        size_t size = PACKET_remaining(pkt);

        /* Simply copy it off for later processing */
        OPENSSL_free(s->ext.scts);
        s->ext.scts = NULL;

        s->ext.scts_len = size;
        if (size > 0) {
            s->ext.scts = OPENSSL_malloc(size);
            if (s->ext.scts == NULL
                    || !PACKET_copy_bytes(pkt, s->ext.scts, size)) {
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

int tls_parse_stoc_npn(SSL *s, PACKET *pkt, X509 *x, size_t chainidx, int *al)
{
    unsigned char *selected;
    unsigned char selected_len;
    PACKET tmppkt;

    /* Check if we are in a renegotiation. If so ignore this extension */
    if (s->s3->tmp.finish_md_len != 0)
        return 1;

    /* We must have requested it. */
    if (s->ctx->ext.npn_select_cb == NULL) {
        *al = SSL_AD_UNSUPPORTED_EXTENSION;
        return 0;
    }

    /* The data must be valid */
    tmppkt = *pkt;
    if (!ssl_next_proto_validate(&tmppkt)) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }
    if (s->ctx->ext.npn_select_cb(s, &selected, &selected_len,
                                  PACKET_data(pkt),
                                  PACKET_remaining(pkt),
                                  s->ctx->ext.npn_select_cb_arg) !=
             SSL_TLSEXT_ERR_OK) {
        *al = SSL_AD_INTERNAL_ERROR;
        return 0;
    }

    /*
     * Could be non-NULL if server has sent multiple NPN extensions in
     * a single Serverhello
     */
    OPENSSL_free(s->ext.npn);
    s->ext.npn = OPENSSL_malloc(selected_len);
    if (s->ext.npn == NULL) {
        *al = SSL_AD_INTERNAL_ERROR;
        return 0;
    }

    memcpy(s->ext.npn, selected, selected_len);
    s->ext.npn_len = selected_len;
    s->s3->npn_seen = 1;

    return 1;
}
#endif

int tls_parse_stoc_alpn(SSL *s, PACKET *pkt, X509 *x, size_t chainidx, int *al)
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
int tls_parse_stoc_use_srtp(SSL *s, PACKET *pkt, X509 *x, size_t chainidx,
                            int *al)
{
    unsigned int id, ct, mki;
    int i;
    STACK_OF(SRTP_PROTECTION_PROFILE) *clnt;
    SRTP_PROTECTION_PROFILE *prof;

    if (!PACKET_get_net_2(pkt, &ct) || ct != 2
            || !PACKET_get_net_2(pkt, &id)
            || !PACKET_get_1(pkt, &mki)
            || PACKET_remaining(pkt) != 0) {
        SSLerr(SSL_F_TLS_PARSE_STOC_USE_SRTP,
               SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    if (mki != 0) {
        /* Must be no MKI, since we never offer one */
        SSLerr(SSL_F_TLS_PARSE_STOC_USE_SRTP, SSL_R_BAD_SRTP_MKI_VALUE);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return 0;
    }

    /* Throw an error if the server gave us an unsolicited extension */
    clnt = SSL_get_srtp_profiles(s);
    if (clnt == NULL) {
        SSLerr(SSL_F_TLS_PARSE_STOC_USE_SRTP, SSL_R_NO_SRTP_PROFILES);
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

    SSLerr(SSL_F_TLS_PARSE_STOC_USE_SRTP,
           SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
    *al = SSL_AD_DECODE_ERROR;
    return 0;
}
#endif

int tls_parse_stoc_etm(SSL *s, PACKET *pkt, X509 *x, size_t chainidx, int *al)
{
    /* Ignore if inappropriate ciphersuite */
    if (!(s->options & SSL_OP_NO_ENCRYPT_THEN_MAC)
            && s->s3->tmp.new_cipher->algorithm_mac != SSL_AEAD
            && s->s3->tmp.new_cipher->algorithm_enc != SSL_RC4)
        s->s3->flags |= TLS1_FLAGS_ENCRYPT_THEN_MAC;

    return 1;
}

int tls_parse_stoc_ems(SSL *s, PACKET *pkt, X509 *x, size_t chainidx, int *al)
{
    s->s3->flags |= TLS1_FLAGS_RECEIVED_EXTMS;
    if (!s->hit)
        s->session->flags |= SSL_SESS_FLAG_EXTMS;

    return 1;
}

int tls_parse_stoc_key_share(SSL *s, PACKET *pkt, X509 *x, size_t chainidx,
                             int *al)
{
#ifndef OPENSSL_NO_TLS1_3
    unsigned int group_id;
    PACKET encoded_pt;
    EVP_PKEY *ckey = s->s3->tmp.pkey, *skey = NULL;

    /* Sanity check */
    if (ckey == NULL) {
        *al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_TLS_PARSE_STOC_KEY_SHARE, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_get_net_2(pkt, &group_id)) {
        *al = SSL_AD_HANDSHAKE_FAILURE;
        SSLerr(SSL_F_TLS_PARSE_STOC_KEY_SHARE, SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    if (group_id != s->s3->group_id) {
        /*
         * This isn't for the group that we sent in the original
         * key_share!
         */
        *al = SSL_AD_HANDSHAKE_FAILURE;
        SSLerr(SSL_F_TLS_PARSE_STOC_KEY_SHARE, SSL_R_BAD_KEY_SHARE);
        return 0;
    }

    if (!PACKET_as_length_prefixed_2(pkt, &encoded_pt)
            || PACKET_remaining(&encoded_pt) == 0) {
        *al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_TLS_PARSE_STOC_KEY_SHARE, SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    skey = ssl_generate_pkey(ckey);
    if (skey == NULL) {
        *al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_TLS_PARSE_STOC_KEY_SHARE, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!EVP_PKEY_set1_tls_encodedpoint(skey, PACKET_data(&encoded_pt),
                                        PACKET_remaining(&encoded_pt))) {
        *al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_TLS_PARSE_STOC_KEY_SHARE, SSL_R_BAD_ECPOINT);
        EVP_PKEY_free(skey);
        return 0;
    }

    if (ssl_derive(s, ckey, skey, 1) == 0) {
        *al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_TLS_PARSE_STOC_KEY_SHARE, ERR_R_INTERNAL_ERROR);
        EVP_PKEY_free(skey);
        return 0;
    }
    EVP_PKEY_free(skey);
#endif

    return 1;
}
