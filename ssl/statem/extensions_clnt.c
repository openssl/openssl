/*
 * Copyright 2016-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/ocsp.h>
#include "../tls_local.h"
#include "internal/cryptlib.h"
#include "statem_local.h"

EXT_RETURN tls_construct_ctos_renegotiate(tls *s, WPACKET *pkt,
                                          unsigned int context, X509 *x,
                                          size_t chainidx)
{
    /* Add RI if renegotiating */
    if (!s->renegotiate)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_renegotiate)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_sub_memcpy_u8(pkt, s->s3.previous_client_finished,
                               s->s3.previous_client_finished_len)
            || !WPACKET_close(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_RENEGOTIATE,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

EXT_RETURN tls_construct_ctos_server_name(tls *s, WPACKET *pkt,
                                          unsigned int context, X509 *x,
                                          size_t chainidx)
{
    if (s->ext.hostname == NULL)
        return EXT_RETURN_NOT_SENT;

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
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_SERVER_NAME,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

/* Push a Max Fragment Len extension into ClientHello */
EXT_RETURN tls_construct_ctos_maxfragmentlen(tls *s, WPACKET *pkt,
                                             unsigned int context, X509 *x,
                                             size_t chainidx)
{
    if (s->ext.max_fragment_len_mode == TLSEXT_max_fragment_length_DISABLED)
        return EXT_RETURN_NOT_SENT;

    /* Add Max Fragment Length extension if client enabled it. */
    /*-
     * 4 bytes for this extension type and extension length
     * 1 byte for the Max Fragment Length code value.
     */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_max_fragment_length)
            /* Sub-packet for Max Fragment Length extension (1 byte) */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u8(pkt, s->ext.max_fragment_len_mode)
            || !WPACKET_close(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_TLS_CONSTRUCT_CTOS_MAXFRAGMENTLEN, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

#ifndef OPENtls_NO_SRP
EXT_RETURN tls_construct_ctos_srp(tls *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    /* Add SRP username if there is one */
    if (s->srp_ctx.login == NULL)
        return EXT_RETURN_NOT_SENT;

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
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_SRP,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
#endif

#ifndef OPENtls_NO_EC
static int use_ecc(tls *s, int max_version)
{
    int i, end, ret = 0;
    unsigned long alg_k, alg_a;
    STACK_OF(tls_CIPHER) *cipher_stack = NULL;
    const uint16_t *pgroups = NULL;
    size_t num_groups, j;

    /* See if we support any ECC ciphersuites */
    if (s->version == tls3_VERSION)
        return 0;

    cipher_stack = tls_get1_supported_ciphers(s);
    end = sk_tls_CIPHER_num(cipher_stack);
    for (i = 0; i < end; i++) {
        const tls_CIPHER *c = sk_tls_CIPHER_value(cipher_stack, i);

        alg_k = c->algorithm_mkey;
        alg_a = c->algorithm_auth;
        if ((alg_k & (tls_kECDHE | tls_kECDHEPSK))
                || (alg_a & tls_aECDSA)
                || c->min_tls >= TLS1_3_VERSION) {
            ret = 1;
            break;
        }
    }
    sk_tls_CIPHER_free(cipher_stack);
    if (!ret)
        return 0;

    /* Check we have at least one EC supported group */
    tls1_get_supported_groups(s, &pgroups, &num_groups);
    for (j = 0; j < num_groups; j++) {
        uint16_t ctmp = pgroups[j];

        if (tls_valid_group(s, ctmp, max_version)
                && tls_group_allowed(s, ctmp, tls_SECOP_CURVE_SUPPORTED))
            return 1;
    }

    return 0;
}

EXT_RETURN tls_construct_ctos_ec_pt_formats(tls *s, WPACKET *pkt,
                                            unsigned int context, X509 *x,
                                            size_t chainidx)
{
    const unsigned char *pformats;
    size_t num_formats;
    int reason, min_version, max_version;

    reason = tls_get_min_max_version(s, &min_version, &max_version, NULL);
    if (reason != 0) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_TLS_CONSTRUCT_CTOS_EC_PT_FORMATS, reason);
        return EXT_RETURN_FAIL;
    }
    if (!use_ecc(s, max_version))
        return EXT_RETURN_NOT_SENT;

    /* Add TLS extension ECPointFormats to the ClientHello message */
    tls1_get_formatlist(s, &pformats, &num_formats);

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_ec_point_formats)
               /* Sub-packet for formats extension */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_sub_memcpy_u8(pkt, pformats, num_formats)
            || !WPACKET_close(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_TLS_CONSTRUCT_CTOS_EC_PT_FORMATS, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
#endif

#if !defined(OPENtls_NO_DH) || !defined(OPENtls_NO_EC)
EXT_RETURN tls_construct_ctos_supported_groups(tls *s, WPACKET *pkt,
                                               unsigned int context, X509 *x,
                                               size_t chainidx)
{
    const uint16_t *pgroups = NULL;
    size_t num_groups = 0, i;
    int min_version, max_version, reason;

    reason = tls_get_min_max_version(s, &min_version, &max_version, NULL);
    if (reason != 0) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_TLS_CONSTRUCT_CTOS_SUPPORTED_GROUPS, reason);
        return EXT_RETURN_FAIL;
    }

#if defined(OPENtls_NO_EC)
    if (max_version < TLS1_3_VERSION)
        return EXT_RETURN_NOT_SENT;
#else
    if (!use_ecc(s, max_version) && max_version < TLS1_3_VERSION)
        return EXT_RETURN_NOT_SENT;
#endif

    /*
     * Add TLS extension supported_groups to the ClientHello message
     */
    tls1_get_supported_groups(s, &pgroups, &num_groups);

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_supported_groups)
               /* Sub-packet for supported_groups extension */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_set_flags(pkt, WPACKET_FLAGS_NON_ZERO_LENGTH)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_TLS_CONSTRUCT_CTOS_SUPPORTED_GROUPS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }
    /* Copy group ID if supported */
    for (i = 0; i < num_groups; i++) {
        uint16_t ctmp = pgroups[i];

        if (tls_valid_group(s, ctmp, max_version)
                && tls_group_allowed(s, ctmp, tls_SECOP_CURVE_SUPPORTED)) {
            if (!WPACKET_put_bytes_u16(pkt, ctmp)) {
                tlsfatal(s, tls_AD_INTERNAL_ERROR,
                         tls_F_TLS_CONSTRUCT_CTOS_SUPPORTED_GROUPS,
                         ERR_R_INTERNAL_ERROR);
                return EXT_RETURN_FAIL;
            }
        }
    }
    if (!WPACKET_close(pkt) || !WPACKET_close(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_TLS_CONSTRUCT_CTOS_SUPPORTED_GROUPS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
#endif

EXT_RETURN tls_construct_ctos_session_ticket(tls *s, WPACKET *pkt,
                                             unsigned int context, X509 *x,
                                             size_t chainidx)
{
    size_t ticklen;

    if (!tls_use_ticket(s))
        return EXT_RETURN_NOT_SENT;

    if (!s->new_session && s->session != NULL
            && s->session->ext.tick != NULL
            && s->session->tls_version != TLS1_3_VERSION) {
        ticklen = s->session->ext.ticklen;
    } else if (s->session && s->ext.session_ticket != NULL
               && s->ext.session_ticket->data != NULL) {
        ticklen = s->ext.session_ticket->length;
        s->session->ext.tick = OPENtls_malloc(ticklen);
        if (s->session->ext.tick == NULL) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR,
                     tls_F_TLS_CONSTRUCT_CTOS_SESSION_TICKET,
                     ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        memcpy(s->session->ext.tick,
               s->ext.session_ticket->data, ticklen);
        s->session->ext.ticklen = ticklen;
    } else {
        ticklen = 0;
    }

    if (ticklen == 0 && s->ext.session_ticket != NULL &&
            s->ext.session_ticket->data == NULL)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_session_ticket)
            || !WPACKET_sub_memcpy_u16(pkt, s->session->ext.tick, ticklen)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_TLS_CONSTRUCT_CTOS_SESSION_TICKET, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

EXT_RETURN tls_construct_ctos_sig_algs(tls *s, WPACKET *pkt,
                                       unsigned int context, X509 *x,
                                       size_t chainidx)
{
    size_t salglen;
    const uint16_t *salg;

    if (!tls_CLIENT_USE_SIGALGS(s))
        return EXT_RETURN_NOT_SENT;

    salglen = tls12_get_psigalgs(s, 1, &salg);
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_signature_algorithms)
               /* Sub-packet for sig-algs extension */
            || !WPACKET_start_sub_packet_u16(pkt)
               /* Sub-packet for the actual list */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !tls12_copy_sigalgs(s, pkt, salg, salglen)
            || !WPACKET_close(pkt)
            || !WPACKET_close(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_SIG_ALGS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

#ifndef OPENtls_NO_OCSP
EXT_RETURN tls_construct_ctos_status_request(tls *s, WPACKET *pkt,
                                             unsigned int context, X509 *x,
                                             size_t chainidx)
{
    int i;

    /* This extension isn't defined for client Certificates */
    if (x != NULL)
        return EXT_RETURN_NOT_SENT;

    if (s->ext.status_type != TLSEXT_STATUSTYPE_ocsp)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_status_request)
               /* Sub-packet for status request extension */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u8(pkt, TLSEXT_STATUSTYPE_ocsp)
               /* Sub-packet for the ids */
            || !WPACKET_start_sub_packet_u16(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }
    for (i = 0; i < sk_OCSP_RESPID_num(s->ext.ocsp.ids); i++) {
        unsigned char *idbytes;
        OCSP_RESPID *id = sk_OCSP_RESPID_value(s->ext.ocsp.ids, i);
        int idlen = i2d_OCSP_RESPID(id, NULL);

        if (idlen <= 0
                   /* Sub-packet for an individual id */
                || !WPACKET_sub_allocate_bytes_u16(pkt, idlen, &idbytes)
                || i2d_OCSP_RESPID(id, &idbytes) != idlen) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR,
                     tls_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST,
                     ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
    }
    if (!WPACKET_close(pkt)
            || !WPACKET_start_sub_packet_u16(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }
    if (s->ext.ocsp.exts) {
        unsigned char *extbytes;
        int extlen = i2d_X509_EXTENSIONS(s->ext.ocsp.exts, NULL);

        if (extlen < 0) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR,
                     tls_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST,
                     ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        if (!WPACKET_allocate_bytes(pkt, extlen, &extbytes)
                || i2d_X509_EXTENSIONS(s->ext.ocsp.exts, &extbytes)
                   != extlen) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR,
                     tls_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST,
                     ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
       }
    }
    if (!WPACKET_close(pkt) || !WPACKET_close(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
#endif

#ifndef OPENtls_NO_NEXTPROTONEG
EXT_RETURN tls_construct_ctos_npn(tls *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    if (s->ctx->ext.npn_select_cb == NULL || !tls_IS_FIRST_HANDSHAKE(s))
        return EXT_RETURN_NOT_SENT;

    /*
     * The client advertises an empty extension to indicate its support
     * for Next Protocol Negotiation
     */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_next_proto_neg)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_NPN,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
#endif

EXT_RETURN tls_construct_ctos_alpn(tls *s, WPACKET *pkt, unsigned int context,
                                   X509 *x, size_t chainidx)
{
    s->s3.alpn_sent = 0;

    if (s->ext.alpn == NULL || !tls_IS_FIRST_HANDSHAKE(s))
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt,
                TLSEXT_TYPE_application_layer_protocol_negotiation)
               /* Sub-packet ALPN extension */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_sub_memcpy_u16(pkt, s->ext.alpn, s->ext.alpn_len)
            || !WPACKET_close(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_ALPN,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }
    s->s3.alpn_sent = 1;

    return EXT_RETURN_SENT;
}


#ifndef OPENtls_NO_SRTP
EXT_RETURN tls_construct_ctos_use_srtp(tls *s, WPACKET *pkt,
                                       unsigned int context, X509 *x,
                                       size_t chainidx)
{
    STACK_OF(SRTP_PROTECTION_PROFILE) *clnt = tls_get_srtp_profiles(s);
    int i, end;

    if (clnt == NULL)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_use_srtp)
               /* Sub-packet for SRTP extension */
            || !WPACKET_start_sub_packet_u16(pkt)
               /* Sub-packet for the protection profile list */
            || !WPACKET_start_sub_packet_u16(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_USE_SRTP,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    end = sk_SRTP_PROTECTION_PROFILE_num(clnt);
    for (i = 0; i < end; i++) {
        const SRTP_PROTECTION_PROFILE *prof =
            sk_SRTP_PROTECTION_PROFILE_value(clnt, i);

        if (prof == NULL || !WPACKET_put_bytes_u16(pkt, prof->id)) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR,
                     tls_F_TLS_CONSTRUCT_CTOS_USE_SRTP, ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
    }
    if (!WPACKET_close(pkt)
               /* Add an empty use_mki value */
            || !WPACKET_put_bytes_u8(pkt, 0)
            || !WPACKET_close(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_USE_SRTP,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
#endif

EXT_RETURN tls_construct_ctos_etm(tls *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    if (s->options & tls_OP_NO_ENCRYPT_THEN_MAC)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_encrypt_then_mac)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_ETM,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

#ifndef OPENtls_NO_CT
EXT_RETURN tls_construct_ctos_sct(tls *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    if (s->ct_validation_callback == NULL)
        return EXT_RETURN_NOT_SENT;

    /* Not defined for client Certificates */
    if (x != NULL)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_signed_certificate_timestamp)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_SCT,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
#endif

EXT_RETURN tls_construct_ctos_ems(tls *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    if (s->options & tls_OP_NO_EXTENDED_MASTER_SECRET)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_extended_master_secret)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_EMS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

EXT_RETURN tls_construct_ctos_supported_versions(tls *s, WPACKET *pkt,
                                                 unsigned int context, X509 *x,
                                                 size_t chainidx)
{
    int currv, min_version, max_version, reason;

    reason = tls_get_min_max_version(s, &min_version, &max_version, NULL);
    if (reason != 0) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_TLS_CONSTRUCT_CTOS_SUPPORTED_VERSIONS, reason);
        return EXT_RETURN_FAIL;
    }

    /*
     * Don't include this if we can't negotiate TLSv1.3. We can do a straight
     * comparison here because we will never be called in DTLS.
     */
    if (max_version < TLS1_3_VERSION)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_supported_versions)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_start_sub_packet_u8(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_TLS_CONSTRUCT_CTOS_SUPPORTED_VERSIONS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    for (currv = max_version; currv >= min_version; currv--) {
        if (!WPACKET_put_bytes_u16(pkt, currv)) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR,
                     tls_F_TLS_CONSTRUCT_CTOS_SUPPORTED_VERSIONS,
                     ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
    }
    if (!WPACKET_close(pkt) || !WPACKET_close(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_TLS_CONSTRUCT_CTOS_SUPPORTED_VERSIONS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

/*
 * Construct a psk_kex_modes extension.
 */
EXT_RETURN tls_construct_ctos_psk_kex_modes(tls *s, WPACKET *pkt,
                                            unsigned int context, X509 *x,
                                            size_t chainidx)
{
#ifndef OPENtls_NO_TLS1_3
    int nodhe = s->options & tls_OP_ALLOW_NO_DHE_KEX;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_psk_kex_modes)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_start_sub_packet_u8(pkt)
            || !WPACKET_put_bytes_u8(pkt, TLSEXT_KEX_MODE_KE_DHE)
            || (nodhe && !WPACKET_put_bytes_u8(pkt, TLSEXT_KEX_MODE_KE))
            || !WPACKET_close(pkt)
            || !WPACKET_close(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_TLS_CONSTRUCT_CTOS_PSK_KEX_MODES, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    s->ext.psk_kex_mode = TLSEXT_KEX_MODE_FLAG_KE_DHE;
    if (nodhe)
        s->ext.psk_kex_mode |= TLSEXT_KEX_MODE_FLAG_KE;
#endif

    return EXT_RETURN_SENT;
}

#ifndef OPENtls_NO_TLS1_3
static int add_key_share(tls *s, WPACKET *pkt, unsigned int curve_id)
{
    unsigned char *encoded_point = NULL;
    EVP_PKEY *key_share_key = NULL;
    size_t encodedlen;

    if (s->s3.tmp.pkey != NULL) {
        if (!otls_assert(s->hello_retry_request == tls_HRR_PENDING)) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_ADD_KEY_SHARE,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        /*
         * Could happen if we got an HRR that wasn't requesting a new key_share
         */
        key_share_key = s->s3.tmp.pkey;
    } else {
        key_share_key = tls_generate_pkey_group(s, curve_id);
        if (key_share_key == NULL) {
            /* tlsfatal() already called */
            return 0;
        }
    }

    /* Encode the public key. */
    encodedlen = EVP_PKEY_get1_tls_encodedpoint(key_share_key,
                                                &encoded_point);
    if (encodedlen == 0) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_ADD_KEY_SHARE, ERR_R_EC_LIB);
        goto err;
    }

    /* Create KeyShareEntry */
    if (!WPACKET_put_bytes_u16(pkt, curve_id)
            || !WPACKET_sub_memcpy_u16(pkt, encoded_point, encodedlen)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_ADD_KEY_SHARE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * TODO(TLS1.3): When changing to send more than one key_share we're
     * going to need to be able to save more than one EVP_PKEY. For now
     * we reuse the existing tmp.pkey
     */
    s->s3.tmp.pkey = key_share_key;
    s->s3.group_id = curve_id;
    OPENtls_free(encoded_point);

    return 1;
 err:
    if (s->s3.tmp.pkey == NULL)
        EVP_PKEY_free(key_share_key);
    OPENtls_free(encoded_point);
    return 0;
}
#endif

EXT_RETURN tls_construct_ctos_key_share(tls *s, WPACKET *pkt,
                                        unsigned int context, X509 *x,
                                        size_t chainidx)
{
#ifndef OPENtls_NO_TLS1_3
    size_t i, num_groups = 0;
    const uint16_t *pgroups = NULL;
    uint16_t curve_id = 0;

    /* key_share extension */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_key_share)
               /* Extension data sub-packet */
            || !WPACKET_start_sub_packet_u16(pkt)
               /* KeyShare list sub-packet */
            || !WPACKET_start_sub_packet_u16(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_KEY_SHARE,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    tls1_get_supported_groups(s, &pgroups, &num_groups);

    /*
     * TODO(TLS1.3): Make the number of key_shares sent configurable. For
     * now, just send one
     */
    if (s->s3.group_id != 0) {
        curve_id = s->s3.group_id;
    } else {
        for (i = 0; i < num_groups; i++) {

            if (!tls_group_allowed(s, pgroups[i], tls_SECOP_CURVE_SUPPORTED))
                continue;

            curve_id = pgroups[i];
            break;
        }
    }

    if (curve_id == 0) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_KEY_SHARE,
                 tls_R_NO_SUITABLE_KEY_SHARE);
        return EXT_RETURN_FAIL;
    }

    if (!add_key_share(s, pkt, curve_id)) {
        /* tlsfatal() already called */
        return EXT_RETURN_FAIL;
    }

    if (!WPACKET_close(pkt) || !WPACKET_close(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_KEY_SHARE,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }
    return EXT_RETURN_SENT;
#else
    return EXT_RETURN_NOT_SENT;
#endif
}

EXT_RETURN tls_construct_ctos_cookie(tls *s, WPACKET *pkt, unsigned int context,
                                     X509 *x, size_t chainidx)
{
    EXT_RETURN ret = EXT_RETURN_FAIL;

    /* Should only be set if we've had an HRR */
    if (s->ext.tls13_cookie_len == 0)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_cookie)
               /* Extension data sub-packet */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_sub_memcpy_u16(pkt, s->ext.tls13_cookie,
                                       s->ext.tls13_cookie_len)
            || !WPACKET_close(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_COOKIE,
                 ERR_R_INTERNAL_ERROR);
        goto end;
    }

    ret = EXT_RETURN_SENT;
 end:
    OPENtls_free(s->ext.tls13_cookie);
    s->ext.tls13_cookie = NULL;
    s->ext.tls13_cookie_len = 0;

    return ret;
}

EXT_RETURN tls_construct_ctos_early_data(tls *s, WPACKET *pkt,
                                         unsigned int context, X509 *x,
                                         size_t chainidx)
{
#ifndef OPENtls_NO_PSK
    char identity[PSK_MAX_IDENTITY_LEN + 1];
#endif  /* OPENtls_NO_PSK */
    const unsigned char *id = NULL;
    size_t idlen = 0;
    tls_SESSION *psksess = NULL;
    tls_SESSION *edsess = NULL;
    const EVP_MD *handmd = NULL;

    if (s->hello_retry_request == tls_HRR_PENDING)
        handmd = tls_handshake_md(s);

    if (s->psk_use_session_cb != NULL
            && (!s->psk_use_session_cb(s, handmd, &id, &idlen, &psksess)
                || (psksess != NULL
                    && psksess->tls_version != TLS1_3_VERSION))) {
        tls_SESSION_free(psksess);
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_EARLY_DATA,
                 tls_R_BAD_PSK);
        return EXT_RETURN_FAIL;
    }

#ifndef OPENtls_NO_PSK
    if (psksess == NULL && s->psk_client_callback != NULL) {
        unsigned char psk[PSK_MAX_PSK_LEN];
        size_t psklen = 0;

        memset(identity, 0, sizeof(identity));
        psklen = s->psk_client_callback(s, NULL, identity, sizeof(identity) - 1,
                                        psk, sizeof(psk));

        if (psklen > PSK_MAX_PSK_LEN) {
            tlsfatal(s, tls_AD_HANDSHAKE_FAILURE,
                     tls_F_TLS_CONSTRUCT_CTOS_EARLY_DATA, ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        } else if (psklen > 0) {
            const unsigned char tls13_aes128gcmsha256_id[] = { 0x13, 0x01 };
            const tls_CIPHER *cipher;

            idlen = strlen(identity);
            if (idlen > PSK_MAX_IDENTITY_LEN) {
                tlsfatal(s, tls_AD_INTERNAL_ERROR,
                         tls_F_TLS_CONSTRUCT_CTOS_EARLY_DATA,
                         ERR_R_INTERNAL_ERROR);
                return EXT_RETURN_FAIL;
            }
            id = (unsigned char *)identity;

            /*
             * We found a PSK using an old style callback. We don't know
             * the digest so we default to SHA256 as per the TLSv1.3 spec
             */
            cipher = tls_CIPHER_find(s, tls13_aes128gcmsha256_id);
            if (cipher == NULL) {
                tlsfatal(s, tls_AD_INTERNAL_ERROR,
                         tls_F_TLS_CONSTRUCT_CTOS_EARLY_DATA,
                         ERR_R_INTERNAL_ERROR);
                return EXT_RETURN_FAIL;
            }

            psksess = tls_SESSION_new();
            if (psksess == NULL
                    || !tls_SESSION_set1_master_key(psksess, psk, psklen)
                    || !tls_SESSION_set_cipher(psksess, cipher)
                    || !tls_SESSION_set_protocol_version(psksess, TLS1_3_VERSION)) {
                tlsfatal(s, tls_AD_INTERNAL_ERROR,
                         tls_F_TLS_CONSTRUCT_CTOS_EARLY_DATA,
                         ERR_R_INTERNAL_ERROR);
                OPENtls_cleanse(psk, psklen);
                return EXT_RETURN_FAIL;
            }
            OPENtls_cleanse(psk, psklen);
        }
    }
#endif  /* OPENtls_NO_PSK */

    tls_SESSION_free(s->psksession);
    s->psksession = psksess;
    if (psksess != NULL) {
        OPENtls_free(s->psksession_id);
        s->psksession_id = OPENtls_memdup(id, idlen);
        if (s->psksession_id == NULL) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR,
                     tls_F_TLS_CONSTRUCT_CTOS_EARLY_DATA, ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        s->psksession_id_len = idlen;
    }

    if (s->early_data_state != tls_EARLY_DATA_CONNECTING
            || (s->session->ext.max_early_data == 0
                && (psksess == NULL || psksess->ext.max_early_data == 0))) {
        s->max_early_data = 0;
        return EXT_RETURN_NOT_SENT;
    }
    edsess = s->session->ext.max_early_data != 0 ? s->session : psksess;
    s->max_early_data = edsess->ext.max_early_data;

    if (edsess->ext.hostname != NULL) {
        if (s->ext.hostname == NULL
                || (s->ext.hostname != NULL
                    && strcmp(s->ext.hostname, edsess->ext.hostname) != 0)) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR,
                     tls_F_TLS_CONSTRUCT_CTOS_EARLY_DATA,
                     tls_R_INCONSISTENT_EARLY_DATA_SNI);
            return EXT_RETURN_FAIL;
        }
    }

    if ((s->ext.alpn == NULL && edsess->ext.alpn_selected != NULL)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_EARLY_DATA,
                 tls_R_INCONSISTENT_EARLY_DATA_ALPN);
        return EXT_RETURN_FAIL;
    }

    /*
     * Verify that we are offering an ALPN protocol consistent with the early
     * data.
     */
    if (edsess->ext.alpn_selected != NULL) {
        PACKET prots, alpnpkt;
        int found = 0;

        if (!PACKET_buf_init(&prots, s->ext.alpn, s->ext.alpn_len)) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR,
                     tls_F_TLS_CONSTRUCT_CTOS_EARLY_DATA, ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        while (PACKET_get_length_prefixed_1(&prots, &alpnpkt)) {
            if (PACKET_equal(&alpnpkt, edsess->ext.alpn_selected,
                             edsess->ext.alpn_selected_len)) {
                found = 1;
                break;
            }
        }
        if (!found) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR,
                     tls_F_TLS_CONSTRUCT_CTOS_EARLY_DATA,
                     tls_R_INCONSISTENT_EARLY_DATA_ALPN);
            return EXT_RETURN_FAIL;
        }
    }

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_early_data)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_close(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_EARLY_DATA,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    /*
     * We set this to rejected here. Later, if the server acknowledges the
     * extension, we set it to accepted.
     */
    s->ext.early_data = tls_EARLY_DATA_REJECTED;
    s->ext.early_data_ok = 1;

    return EXT_RETURN_SENT;
}

#define F5_WORKAROUND_MIN_MSG_LEN   0xff
#define F5_WORKAROUND_MAX_MSG_LEN   0x200

/*
 * PSK pre binder overhead =
 *  2 bytes for TLSEXT_TYPE_psk
 *  2 bytes for extension length
 *  2 bytes for identities list length
 *  2 bytes for identity length
 *  4 bytes for obfuscated_ticket_age
 *  2 bytes for binder list length
 *  1 byte for binder length
 * The above excludes the number of bytes for the identity itself and the
 * subsequent binder bytes
 */
#define PSK_PRE_BINDER_OVERHEAD (2 + 2 + 2 + 2 + 4 + 2 + 1)

EXT_RETURN tls_construct_ctos_padding(tls *s, WPACKET *pkt,
                                      unsigned int context, X509 *x,
                                      size_t chainidx)
{
    unsigned char *padbytes;
    size_t hlen;

    if ((s->options & tls_OP_TLSEXT_PADDING) == 0)
        return EXT_RETURN_NOT_SENT;

    /*
     * Add padding to workaround bugs in F5 terminators. See RFC7685.
     * This code calculates the length of all extensions added so far but
     * excludes the PSK extension (because that MUST be written last). Therefore
     * this extension MUST always appear second to last.
     */
    if (!WPACKET_get_total_written(pkt, &hlen)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_PADDING,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    /*
     * If we're going to send a PSK then that will be written out after this
     * extension, so we need to calculate how long it is going to be.
     */
    if (s->session->tls_version == TLS1_3_VERSION
            && s->session->ext.ticklen != 0
            && s->session->cipher != NULL) {
        const EVP_MD *md = tls_md(s->session->cipher->algorithm2);

        if (md != NULL) {
            /*
             * Add the fixed PSK overhead, the identity length and the binder
             * length.
             */
            hlen +=  PSK_PRE_BINDER_OVERHEAD + s->session->ext.ticklen
                     + EVP_MD_size(md);
        }
    }

    if (hlen > F5_WORKAROUND_MIN_MSG_LEN && hlen < F5_WORKAROUND_MAX_MSG_LEN) {
        /* Calculate the amount of padding we need to add */
        hlen = F5_WORKAROUND_MAX_MSG_LEN - hlen;

        /*
         * Take off the size of extension header itself (2 bytes for type and
         * 2 bytes for length bytes), but ensure that the extension is at least
         * 1 byte long so as not to have an empty extension last (WebSphere 7.x,
         * 8.x are intolerant of that condition)
         */
        if (hlen > 4)
            hlen -= 4;
        else
            hlen = 1;

        if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_padding)
                || !WPACKET_sub_allocate_bytes_u16(pkt, hlen, &padbytes)) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_PADDING,
                     ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        memset(padbytes, 0, hlen);
    }

    return EXT_RETURN_SENT;
}

/*
 * Construct the pre_shared_key extension
 */
EXT_RETURN tls_construct_ctos_psk(tls *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
#ifndef OPENtls_NO_TLS1_3
    uint32_t now, agesec, agems = 0;
    size_t reshashsize = 0, pskhashsize = 0, binderoffset, msglen;
    unsigned char *resbinder = NULL, *pskbinder = NULL, *msgstart = NULL;
    const EVP_MD *handmd = NULL, *mdres = NULL, *mdpsk = NULL;
    int dores = 0;

    s->ext.tick_identity = 0;

    /*
     * Note: At this stage of the code we only support adding a single
     * resumption PSK. If we add support for multiple PSKs then the length
     * calculations in the padding extension will need to be adjusted.
     */

    /*
     * If this is an incompatible or new session then we have nothing to resume
     * so don't add this extension.
     */
    if (s->session->tls_version != TLS1_3_VERSION
            || (s->session->ext.ticklen == 0 && s->psksession == NULL))
        return EXT_RETURN_NOT_SENT;

    if (s->hello_retry_request == tls_HRR_PENDING)
        handmd = tls_handshake_md(s);

    if (s->session->ext.ticklen != 0) {
        /* Get the digest associated with the ciphersuite in the session */
        if (s->session->cipher == NULL) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_PSK,
                     ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        mdres = tls_md(s->session->cipher->algorithm2);
        if (mdres == NULL) {
            /*
             * Don't recognize this cipher so we can't use the session.
             * Ignore it
             */
            goto dopsksess;
        }

        if (s->hello_retry_request == tls_HRR_PENDING && mdres != handmd) {
            /*
             * Selected ciphersuite hash does not match the hash for the session
             * so we can't use it.
             */
            goto dopsksess;
        }

        /*
         * Technically the C standard just says time() returns a time_t and says
         * nothing about the encoding of that type. In practice most
         * implementations follow POSIX which holds it as an integral type in
         * seconds since epoch. We've already made the assumption that we can do
         * this in multiple places in the code, so portability shouldn't be an
         * issue.
         */
        now = (uint32_t)time(NULL);
        agesec = now - (uint32_t)s->session->time;
        /*
         * We calculate the age in seconds but the server may work in ms. Due to
         * rounding errors we could overestimate the age by up to 1s. It is
         * better to underestimate it. Otherwise, if the RTT is very short, when
         * the server calculates the age reported by the client it could be
         * bigger than the age calculated on the server - which should never
         * happen.
         */
        if (agesec > 0)
            agesec--;

        if (s->session->ext.tick_lifetime_hint < agesec) {
            /* Ticket is too old. Ignore it. */
            goto dopsksess;
        }

        /*
         * Calculate age in ms. We're just doing it to nearest second. Should be
         * good enough.
         */
        agems = agesec * (uint32_t)1000;

        if (agesec != 0 && agems / (uint32_t)1000 != agesec) {
            /*
             * Overflow. Shouldn't happen unless this is a *really* old session.
             * If so we just ignore it.
             */
            goto dopsksess;
        }

        /*
         * Obfuscate the age. Overflow here is fine, this addition is supposed
         * to be mod 2^32.
         */
        agems += s->session->ext.tick_age_add;

        reshashsize = EVP_MD_size(mdres);
        s->ext.tick_identity++;
        dores = 1;
    }

 dopsksess:
    if (!dores && s->psksession == NULL)
        return EXT_RETURN_NOT_SENT;

    if (s->psksession != NULL) {
        mdpsk = tls_md(s->psksession->cipher->algorithm2);
        if (mdpsk == NULL) {
            /*
             * Don't recognize this cipher so we can't use the session.
             * If this happens it's an application bug.
             */
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_PSK,
                     tls_R_BAD_PSK);
            return EXT_RETURN_FAIL;
        }

        if (s->hello_retry_request == tls_HRR_PENDING && mdpsk != handmd) {
            /*
             * Selected ciphersuite hash does not match the hash for the PSK
             * session. This is an application bug.
             */
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_PSK,
                     tls_R_BAD_PSK);
            return EXT_RETURN_FAIL;
        }

        pskhashsize = EVP_MD_size(mdpsk);
    }

    /* Create the extension, but skip over the binder for now */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_psk)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_start_sub_packet_u16(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_PSK,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    if (dores) {
        if (!WPACKET_sub_memcpy_u16(pkt, s->session->ext.tick,
                                           s->session->ext.ticklen)
                || !WPACKET_put_bytes_u32(pkt, agems)) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_PSK,
                     ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
    }

    if (s->psksession != NULL) {
        if (!WPACKET_sub_memcpy_u16(pkt, s->psksession_id,
                                    s->psksession_id_len)
                || !WPACKET_put_bytes_u32(pkt, 0)) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_PSK,
                     ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        s->ext.tick_identity++;
    }

    if (!WPACKET_close(pkt)
            || !WPACKET_get_total_written(pkt, &binderoffset)
            || !WPACKET_start_sub_packet_u16(pkt)
            || (dores
                && !WPACKET_sub_allocate_bytes_u8(pkt, reshashsize, &resbinder))
            || (s->psksession != NULL
                && !WPACKET_sub_allocate_bytes_u8(pkt, pskhashsize, &pskbinder))
            || !WPACKET_close(pkt)
            || !WPACKET_close(pkt)
            || !WPACKET_get_total_written(pkt, &msglen)
               /*
                * We need to fill in all the sub-packet lengths now so we can
                * calculate the HMAC of the message up to the binders
                */
            || !WPACKET_fill_lengths(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_CONSTRUCT_CTOS_PSK,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    msgstart = WPACKET_get_curr(pkt) - msglen;

    if (dores
            && tls_psk_do_binder(s, mdres, msgstart, binderoffset, NULL,
                                 resbinder, s->session, 1, 0) != 1) {
        /* tlsfatal() already called */
        return EXT_RETURN_FAIL;
    }

    if (s->psksession != NULL
            && tls_psk_do_binder(s, mdpsk, msgstart, binderoffset, NULL,
                                 pskbinder, s->psksession, 1, 1) != 1) {
        /* tlsfatal() already called */
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
#else
    return EXT_RETURN_NOT_SENT;
#endif
}

EXT_RETURN tls_construct_ctos_post_handshake_auth(tls *s, WPACKET *pkt,
                                                  unsigned int context,
                                                  X509 *x, size_t chainidx)
{
#ifndef OPENtls_NO_TLS1_3
    if (!s->pha_enabled)
        return EXT_RETURN_NOT_SENT;

    /* construct extension - 0 length, no contents */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_post_handshake_auth)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_close(pkt)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_TLS_CONSTRUCT_CTOS_POST_HANDSHAKE_AUTH,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    s->post_handshake_auth = tls_PHA_EXT_SENT;

    return EXT_RETURN_SENT;
#else
    return EXT_RETURN_NOT_SENT;
#endif
}


/*
 * Parse the server's renegotiation binding and abort if it's not right
 */
int tls_parse_stoc_renegotiate(tls *s, PACKET *pkt, unsigned int context,
                               X509 *x, size_t chainidx)
{
    size_t expected_len = s->s3.previous_client_finished_len
        + s->s3.previous_server_finished_len;
    size_t ilen;
    const unsigned char *data;

    /* Check for logic errors */
    if (!otls_assert(expected_len == 0
                     || s->s3.previous_client_finished_len != 0)
        || !otls_assert(expected_len == 0
                        || s->s3.previous_server_finished_len != 0)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_PARSE_STOC_RENEGOTIATE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Parse the length byte */
    if (!PACKET_get_1_len(pkt, &ilen)) {
        tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_TLS_PARSE_STOC_RENEGOTIATE,
                 tls_R_RENEGOTIATION_ENCODING_ERR);
        return 0;
    }

    /* Consistency check */
    if (PACKET_remaining(pkt) != ilen) {
        tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_TLS_PARSE_STOC_RENEGOTIATE,
                 tls_R_RENEGOTIATION_ENCODING_ERR);
        return 0;
    }

    /* Check that the extension matches */
    if (ilen != expected_len) {
        tlsfatal(s, tls_AD_ILLEGAL_PARAMETER, tls_F_TLS_PARSE_STOC_RENEGOTIATE,
                 tls_R_RENEGOTIATION_MISMATCH);
        return 0;
    }

    if (!PACKET_get_bytes(pkt, &data, s->s3.previous_client_finished_len)
        || memcmp(data, s->s3.previous_client_finished,
                  s->s3.previous_client_finished_len) != 0) {
        tlsfatal(s, tls_AD_ILLEGAL_PARAMETER, tls_F_TLS_PARSE_STOC_RENEGOTIATE,
                 tls_R_RENEGOTIATION_MISMATCH);
        return 0;
    }

    if (!PACKET_get_bytes(pkt, &data, s->s3.previous_server_finished_len)
        || memcmp(data, s->s3.previous_server_finished,
                  s->s3.previous_server_finished_len) != 0) {
        tlsfatal(s, tls_AD_ILLEGAL_PARAMETER, tls_F_TLS_PARSE_STOC_RENEGOTIATE,
                 tls_R_RENEGOTIATION_MISMATCH);
        return 0;
    }
    s->s3.send_connection_binding = 1;

    return 1;
}

/* Parse the server's max fragment len extension packet */
int tls_parse_stoc_maxfragmentlen(tls *s, PACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    unsigned int value;

    if (PACKET_remaining(pkt) != 1 || !PACKET_get_1(pkt, &value)) {
        tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_TLS_PARSE_STOC_MAXFRAGMENTLEN,
                 tls_R_BAD_EXTENSION);
        return 0;
    }

    /* |value| should contains a valid max-fragment-length code. */
    if (!IS_MAX_FRAGMENT_LENGTH_EXT_VALID(value)) {
        tlsfatal(s, tls_AD_ILLEGAL_PARAMETER,
                 tls_F_TLS_PARSE_STOC_MAXFRAGMENTLEN,
                 tls_R_tls3_EXT_INVALID_MAX_FRAGMENT_LENGTH);
        return 0;
    }

    /* Must be the same value as client-configured one who was sent to server */
    /*-
     * RFC 6066: if a client receives a maximum fragment length negotiation
     * response that differs from the length it requested, ...
     * It must abort with tls_AD_ILLEGAL_PARAMETER alert
     */
    if (value != s->ext.max_fragment_len_mode) {
        tlsfatal(s, tls_AD_ILLEGAL_PARAMETER,
                 tls_F_TLS_PARSE_STOC_MAXFRAGMENTLEN,
                 tls_R_tls3_EXT_INVALID_MAX_FRAGMENT_LENGTH);
        return 0;
    }

    /*
     * Maximum Fragment Length Negotiation succeeded.
     * The negotiated Maximum Fragment Length is binding now.
     */
    s->session->ext.max_fragment_len_mode = value;

    return 1;
}

int tls_parse_stoc_server_name(tls *s, PACKET *pkt, unsigned int context,
                               X509 *x, size_t chainidx)
{
    if (s->ext.hostname == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_PARSE_STOC_SERVER_NAME,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (PACKET_remaining(pkt) > 0) {
        tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_TLS_PARSE_STOC_SERVER_NAME,
                 tls_R_BAD_EXTENSION);
        return 0;
    }

    if (!s->hit) {
        if (s->session->ext.hostname != NULL) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_PARSE_STOC_SERVER_NAME,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        s->session->ext.hostname = OPENtls_strdup(s->ext.hostname);
        if (s->session->ext.hostname == NULL) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_PARSE_STOC_SERVER_NAME,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    return 1;
}

#ifndef OPENtls_NO_EC
int tls_parse_stoc_ec_pt_formats(tls *s, PACKET *pkt, unsigned int context,
                                 X509 *x, size_t chainidx)
{
    size_t ecpointformats_len;
    PACKET ecptformatlist;

    if (!PACKET_as_length_prefixed_1(pkt, &ecptformatlist)) {
        tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_TLS_PARSE_STOC_EC_PT_FORMATS,
                 tls_R_BAD_EXTENSION);
        return 0;
    }
    if (!s->hit) {
        ecpointformats_len = PACKET_remaining(&ecptformatlist);
        if (ecpointformats_len == 0) {
            tlsfatal(s, tls_AD_DECODE_ERROR,
                     tls_F_TLS_PARSE_STOC_EC_PT_FORMATS, tls_R_BAD_LENGTH);
            return 0;
        }

        s->ext.peer_ecpointformats_len = 0;
        OPENtls_free(s->ext.peer_ecpointformats);
        s->ext.peer_ecpointformats = OPENtls_malloc(ecpointformats_len);
        if (s->ext.peer_ecpointformats == NULL) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR,
                     tls_F_TLS_PARSE_STOC_EC_PT_FORMATS, ERR_R_INTERNAL_ERROR);
            return 0;
        }

        s->ext.peer_ecpointformats_len = ecpointformats_len;

        if (!PACKET_copy_bytes(&ecptformatlist,
                               s->ext.peer_ecpointformats,
                               ecpointformats_len)) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR,
                     tls_F_TLS_PARSE_STOC_EC_PT_FORMATS, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    return 1;
}
#endif

int tls_parse_stoc_session_ticket(tls *s, PACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    if (s->ext.session_ticket_cb != NULL &&
        !s->ext.session_ticket_cb(s, PACKET_data(pkt),
                              PACKET_remaining(pkt),
                              s->ext.session_ticket_cb_arg)) {
        tlsfatal(s, tls_AD_HANDSHAKE_FAILURE,
                 tls_F_TLS_PARSE_STOC_SESSION_TICKET, tls_R_BAD_EXTENSION);
        return 0;
    }

    if (!tls_use_ticket(s)) {
        tlsfatal(s, tls_AD_UNSUPPORTED_EXTENSION,
                 tls_F_TLS_PARSE_STOC_SESSION_TICKET, tls_R_BAD_EXTENSION);
        return 0;
    }
    if (PACKET_remaining(pkt) > 0) {
        tlsfatal(s, tls_AD_DECODE_ERROR,
                 tls_F_TLS_PARSE_STOC_SESSION_TICKET, tls_R_BAD_EXTENSION);
        return 0;
    }

    s->ext.ticket_expected = 1;

    return 1;
}

#ifndef OPENtls_NO_OCSP
int tls_parse_stoc_status_request(tls *s, PACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    if (context == tls_EXT_TLS1_3_CERTIFICATE_REQUEST) {
        /* We ignore this if the server sends a CertificateRequest */
        /* TODO(TLS1.3): Add support for this */
        return 1;
    }

    /*
     * MUST only be sent if we've requested a status
     * request message. In TLS <= 1.2 it must also be empty.
     */
    if (s->ext.status_type != TLSEXT_STATUSTYPE_ocsp) {
        tlsfatal(s, tls_AD_UNSUPPORTED_EXTENSION,
                 tls_F_TLS_PARSE_STOC_STATUS_REQUEST, tls_R_BAD_EXTENSION);
        return 0;
    }
    if (!tls_IS_TLS13(s) && PACKET_remaining(pkt) > 0) {
        tlsfatal(s, tls_AD_DECODE_ERROR,
                 tls_F_TLS_PARSE_STOC_STATUS_REQUEST, tls_R_BAD_EXTENSION);
        return 0;
    }

    if (tls_IS_TLS13(s)) {
        /* We only know how to handle this if it's for the first Certificate in
         * the chain. We ignore any other responses.
         */
        if (chainidx != 0)
            return 1;

        /* tlsfatal() already called */
        return tls_process_cert_status_body(s, pkt);
    }

    /* Set flag to expect CertificateStatus message */
    s->ext.status_expected = 1;

    return 1;
}
#endif


#ifndef OPENtls_NO_CT
int tls_parse_stoc_sct(tls *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    if (context == tls_EXT_TLS1_3_CERTIFICATE_REQUEST) {
        /* We ignore this if the server sends it in a CertificateRequest */
        /* TODO(TLS1.3): Add support for this */
        return 1;
    }

    /*
     * Only take it if we asked for it - i.e if there is no CT validation
     * callback set, then a custom extension MAY be processing it, so we
     * need to let control continue to flow to that.
     */
    if (s->ct_validation_callback != NULL) {
        size_t size = PACKET_remaining(pkt);

        /* Simply copy it off for later processing */
        OPENtls_free(s->ext.scts);
        s->ext.scts = NULL;

        s->ext.scts_len = (uint16_t)size;
        if (size > 0) {
            s->ext.scts = OPENtls_malloc(size);
            if (s->ext.scts == NULL
                    || !PACKET_copy_bytes(pkt, s->ext.scts, size)) {
                tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_PARSE_STOC_SCT,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }
    } else {
        ENDPOINT role = (context & tls_EXT_TLS1_2_SERVER_HELLO) != 0
                        ? ENDPOINT_CLIENT : ENDPOINT_BOTH;

        /*
         * If we didn't ask for it then there must be a custom extension,
         * otherwise this is unsolicited.
         */
        if (custom_ext_find(&s->cert->custext, role,
                            TLSEXT_TYPE_signed_certificate_timestamp,
                            NULL) == NULL) {
            tlsfatal(s, TLS1_AD_UNSUPPORTED_EXTENSION, tls_F_TLS_PARSE_STOC_SCT,
                     tls_R_BAD_EXTENSION);
            return 0;
        }

        if (!custom_ext_parse(s, context,
                             TLSEXT_TYPE_signed_certificate_timestamp,
                             PACKET_data(pkt), PACKET_remaining(pkt),
                             x, chainidx)) {
            /* tlsfatal already called */
            return 0;
        }
    }

    return 1;
}
#endif


#ifndef OPENtls_NO_NEXTPROTONEG
/*
 * tls_next_proto_validate validates a Next Protocol Negotiation block. No
 * elements of zero length are allowed and the set of elements must exactly
 * fill the length of the block. Returns 1 on success or 0 on failure.
 */
static int tls_next_proto_validate(tls *s, PACKET *pkt)
{
    PACKET tmp_protocol;

    while (PACKET_remaining(pkt)) {
        if (!PACKET_get_length_prefixed_1(pkt, &tmp_protocol)
            || PACKET_remaining(&tmp_protocol) == 0) {
            tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_tls_NEXT_PROTO_VALIDATE,
                     tls_R_BAD_EXTENSION);
            return 0;
        }
    }

    return 1;
}

int tls_parse_stoc_npn(tls *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    unsigned char *selected;
    unsigned char selected_len;
    PACKET tmppkt;

    /* Check if we are in a renegotiation. If so ignore this extension */
    if (!tls_IS_FIRST_HANDSHAKE(s))
        return 1;

    /* We must have requested it. */
    if (s->ctx->ext.npn_select_cb == NULL) {
        tlsfatal(s, tls_AD_UNSUPPORTED_EXTENSION, tls_F_TLS_PARSE_STOC_NPN,
                 tls_R_BAD_EXTENSION);
        return 0;
    }

    /* The data must be valid */
    tmppkt = *pkt;
    if (!tls_next_proto_validate(s, &tmppkt)) {
        /* tlsfatal() already called */
        return 0;
    }
    if (s->ctx->ext.npn_select_cb(s, &selected, &selected_len,
                                  PACKET_data(pkt),
                                  PACKET_remaining(pkt),
                                  s->ctx->ext.npn_select_cb_arg) !=
             tls_TLSEXT_ERR_OK) {
        tlsfatal(s, tls_AD_HANDSHAKE_FAILURE, tls_F_TLS_PARSE_STOC_NPN,
                 tls_R_BAD_EXTENSION);
        return 0;
    }

    /*
     * Could be non-NULL if server has sent multiple NPN extensions in
     * a single Serverhello
     */
    OPENtls_free(s->ext.npn);
    s->ext.npn = OPENtls_malloc(selected_len);
    if (s->ext.npn == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_PARSE_STOC_NPN,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    memcpy(s->ext.npn, selected, selected_len);
    s->ext.npn_len = selected_len;
    s->s3.npn_seen = 1;

    return 1;
}
#endif

int tls_parse_stoc_alpn(tls *s, PACKET *pkt, unsigned int context, X509 *x,
                        size_t chainidx)
{
    size_t len;

    /* We must have requested it. */
    if (!s->s3.alpn_sent) {
        tlsfatal(s, tls_AD_UNSUPPORTED_EXTENSION, tls_F_TLS_PARSE_STOC_ALPN,
                 tls_R_BAD_EXTENSION);
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
        tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_TLS_PARSE_STOC_ALPN,
                 tls_R_BAD_EXTENSION);
        return 0;
    }
    OPENtls_free(s->s3.alpn_selected);
    s->s3.alpn_selected = OPENtls_malloc(len);
    if (s->s3.alpn_selected == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_PARSE_STOC_ALPN,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (!PACKET_copy_bytes(pkt, s->s3.alpn_selected, len)) {
        tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_TLS_PARSE_STOC_ALPN,
                 tls_R_BAD_EXTENSION);
        return 0;
    }
    s->s3.alpn_selected_len = len;

    if (s->session->ext.alpn_selected == NULL
            || s->session->ext.alpn_selected_len != len
            || memcmp(s->session->ext.alpn_selected, s->s3.alpn_selected, len)
               != 0) {
        /* ALPN not consistent with the old session so cannot use early_data */
        s->ext.early_data_ok = 0;
    }
    if (!s->hit) {
        /*
         * This is a new session and so alpn_selected should have been
         * initialised to NULL. We should update it with the selected ALPN.
         */
        if (!otls_assert(s->session->ext.alpn_selected == NULL)) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_PARSE_STOC_ALPN,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        s->session->ext.alpn_selected =
            OPENtls_memdup(s->s3.alpn_selected, s->s3.alpn_selected_len);
        if (s->session->ext.alpn_selected == NULL) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_PARSE_STOC_ALPN,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        s->session->ext.alpn_selected_len = s->s3.alpn_selected_len;
    }

    return 1;
}

#ifndef OPENtls_NO_SRTP
int tls_parse_stoc_use_srtp(tls *s, PACKET *pkt, unsigned int context, X509 *x,
                            size_t chainidx)
{
    unsigned int id, ct, mki;
    int i;
    STACK_OF(SRTP_PROTECTION_PROFILE) *clnt;
    SRTP_PROTECTION_PROFILE *prof;

    if (!PACKET_get_net_2(pkt, &ct) || ct != 2
            || !PACKET_get_net_2(pkt, &id)
            || !PACKET_get_1(pkt, &mki)
            || PACKET_remaining(pkt) != 0) {
        tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_TLS_PARSE_STOC_USE_SRTP,
                 tls_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        return 0;
    }

    if (mki != 0) {
        /* Must be no MKI, since we never offer one */
        tlsfatal(s, tls_AD_ILLEGAL_PARAMETER, tls_F_TLS_PARSE_STOC_USE_SRTP,
                 tls_R_BAD_SRTP_MKI_VALUE);
        return 0;
    }

    /* Throw an error if the server gave us an unsolicited extension */
    clnt = tls_get_srtp_profiles(s);
    if (clnt == NULL) {
        tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_TLS_PARSE_STOC_USE_SRTP,
                 tls_R_NO_SRTP_PROFILES);
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
            return 1;
        }
    }

    tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_TLS_PARSE_STOC_USE_SRTP,
             tls_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
    return 0;
}
#endif

int tls_parse_stoc_etm(tls *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    /* Ignore if inappropriate ciphersuite */
    if (!(s->options & tls_OP_NO_ENCRYPT_THEN_MAC)
            && s->s3.tmp.new_cipher->algorithm_mac != tls_AEAD
            && s->s3.tmp.new_cipher->algorithm_enc != tls_RC4)
        s->ext.use_etm = 1;

    return 1;
}

int tls_parse_stoc_ems(tls *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    if (s->options & tls_OP_NO_EXTENDED_MASTER_SECRET)
        return 1;
    s->s3.flags |= TLS1_FLAGS_RECEIVED_EXTMS;
    if (!s->hit)
        s->session->flags |= tls_SESS_FLAG_EXTMS;

    return 1;
}

int tls_parse_stoc_supported_versions(tls *s, PACKET *pkt, unsigned int context,
                                      X509 *x, size_t chainidx)
{
    unsigned int version;

    if (!PACKET_get_net_2(pkt, &version)
            || PACKET_remaining(pkt) != 0) {
        tlsfatal(s, tls_AD_DECODE_ERROR,
                 tls_F_TLS_PARSE_STOC_SUPPORTED_VERSIONS,
                 tls_R_LENGTH_MISMATCH);
        return 0;
    }

    /*
     * The only protocol version we support which is valid in this extension in
     * a ServerHello is TLSv1.3 therefore we shouldn't be getting anything else.
     */
    if (version != TLS1_3_VERSION) {
        tlsfatal(s, tls_AD_ILLEGAL_PARAMETER,
                 tls_F_TLS_PARSE_STOC_SUPPORTED_VERSIONS,
                 tls_R_BAD_PROTOCOL_VERSION_NUMBER);
        return 0;
    }

    /* We ignore this extension for HRRs except to sanity check it */
    if (context == tls_EXT_TLS1_3_HELLO_RETRY_REQUEST)
        return 1;

    /* We just set it here. We validate it in tls_choose_client_version */
    s->version = version;

    return 1;
}

int tls_parse_stoc_key_share(tls *s, PACKET *pkt, unsigned int context, X509 *x,
                             size_t chainidx)
{
#ifndef OPENtls_NO_TLS1_3
    unsigned int group_id;
    PACKET encoded_pt;
    EVP_PKEY *ckey = s->s3.tmp.pkey, *skey = NULL;

    /* Sanity check */
    if (ckey == NULL || s->s3.peer_tmp != NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_PARSE_STOC_KEY_SHARE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_get_net_2(pkt, &group_id)) {
        tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_TLS_PARSE_STOC_KEY_SHARE,
                 tls_R_LENGTH_MISMATCH);
        return 0;
    }

    if ((context & tls_EXT_TLS1_3_HELLO_RETRY_REQUEST) != 0) {
        const uint16_t *pgroups = NULL;
        size_t i, num_groups;

        if (PACKET_remaining(pkt) != 0) {
            tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_TLS_PARSE_STOC_KEY_SHARE,
                     tls_R_LENGTH_MISMATCH);
            return 0;
        }

        /*
         * It is an error if the HelloRetryRequest wants a key_share that we
         * already sent in the first ClientHello
         */
        if (group_id == s->s3.group_id) {
            tlsfatal(s, tls_AD_ILLEGAL_PARAMETER,
                     tls_F_TLS_PARSE_STOC_KEY_SHARE, tls_R_BAD_KEY_SHARE);
            return 0;
        }

        /* Validate the selected group is one we support */
        tls1_get_supported_groups(s, &pgroups, &num_groups);
        for (i = 0; i < num_groups; i++) {
            if (group_id == pgroups[i])
                break;
        }
        if (i >= num_groups
                || !tls_group_allowed(s, group_id, tls_SECOP_CURVE_SUPPORTED)) {
            tlsfatal(s, tls_AD_ILLEGAL_PARAMETER,
                     tls_F_TLS_PARSE_STOC_KEY_SHARE, tls_R_BAD_KEY_SHARE);
            return 0;
        }

        s->s3.group_id = group_id;
        EVP_PKEY_free(s->s3.tmp.pkey);
        s->s3.tmp.pkey = NULL;
        return 1;
    }

    if (group_id != s->s3.group_id) {
        /*
         * This isn't for the group that we sent in the original
         * key_share!
         */
        tlsfatal(s, tls_AD_ILLEGAL_PARAMETER, tls_F_TLS_PARSE_STOC_KEY_SHARE,
                 tls_R_BAD_KEY_SHARE);
        return 0;
    }

    if (!PACKET_as_length_prefixed_2(pkt, &encoded_pt)
            || PACKET_remaining(&encoded_pt) == 0) {
        tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_TLS_PARSE_STOC_KEY_SHARE,
                 tls_R_LENGTH_MISMATCH);
        return 0;
    }

    skey = EVP_PKEY_new();
    if (skey == NULL || EVP_PKEY_copy_parameters(skey, ckey) <= 0) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_PARSE_STOC_KEY_SHARE,
                 ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!EVP_PKEY_set1_tls_encodedpoint(skey, PACKET_data(&encoded_pt),
                                        PACKET_remaining(&encoded_pt))) {
        tlsfatal(s, tls_AD_ILLEGAL_PARAMETER, tls_F_TLS_PARSE_STOC_KEY_SHARE,
                 tls_R_BAD_ECPOINT);
        EVP_PKEY_free(skey);
        return 0;
    }

    if (tls_derive(s, ckey, skey, 1) == 0) {
        /* tlsfatal() already called */
        EVP_PKEY_free(skey);
        return 0;
    }
    s->s3.peer_tmp = skey;
#endif

    return 1;
}

int tls_parse_stoc_cookie(tls *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    PACKET cookie;

    if (!PACKET_as_length_prefixed_2(pkt, &cookie)
            || !PACKET_memdup(&cookie, &s->ext.tls13_cookie,
                              &s->ext.tls13_cookie_len)) {
        tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_TLS_PARSE_STOC_COOKIE,
                 tls_R_LENGTH_MISMATCH);
        return 0;
    }

    return 1;
}

int tls_parse_stoc_early_data(tls *s, PACKET *pkt, unsigned int context,
                              X509 *x, size_t chainidx)
{
    if (context == tls_EXT_TLS1_3_NEW_SESSION_TICKET) {
        unsigned long max_early_data;

        if (!PACKET_get_net_4(pkt, &max_early_data)
                || PACKET_remaining(pkt) != 0) {
            tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_TLS_PARSE_STOC_EARLY_DATA,
                     tls_R_INVALID_MAX_EARLY_DATA);
            return 0;
        }

        s->session->ext.max_early_data = max_early_data;

        return 1;
    }

    if (PACKET_remaining(pkt) != 0) {
        tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_TLS_PARSE_STOC_EARLY_DATA,
                 tls_R_BAD_EXTENSION);
        return 0;
    }

    if (!s->ext.early_data_ok
            || !s->hit) {
        /*
         * If we get here then we didn't send early data, or we didn't resume
         * using the first identity, or the SNI/ALPN is not consistent so the
         * server should not be accepting it.
         */
        tlsfatal(s, tls_AD_ILLEGAL_PARAMETER, tls_F_TLS_PARSE_STOC_EARLY_DATA,
                 tls_R_BAD_EXTENSION);
        return 0;
    }

    s->ext.early_data = tls_EARLY_DATA_ACCEPTED;

    return 1;
}

int tls_parse_stoc_psk(tls *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
#ifndef OPENtls_NO_TLS1_3
    unsigned int identity;

    if (!PACKET_get_net_2(pkt, &identity) || PACKET_remaining(pkt) != 0) {
        tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_TLS_PARSE_STOC_PSK,
                 tls_R_LENGTH_MISMATCH);
        return 0;
    }

    if (identity >= (unsigned int)s->ext.tick_identity) {
        tlsfatal(s, tls_AD_ILLEGAL_PARAMETER, tls_F_TLS_PARSE_STOC_PSK,
                 tls_R_BAD_PSK_IDENTITY);
        return 0;
    }

    /*
     * Session resumption tickets are always sent before PSK tickets. If the
     * ticket index is 0 then it must be for a session resumption ticket if we
     * sent two tickets, or if we didn't send a PSK ticket.
     */
    if (identity == 0 && (s->psksession == NULL || s->ext.tick_identity == 2)) {
        s->hit = 1;
        tls_SESSION_free(s->psksession);
        s->psksession = NULL;
        return 1;
    }

    if (s->psksession == NULL) {
        /* Should never happen */
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS_PARSE_STOC_PSK,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * If we used the external PSK for sending early_data then s->early_secret
     * is already set up, so don't overwrite it. Otherwise we copy the
     * early_secret across that we generated earlier.
     */
    if ((s->early_data_state != tls_EARLY_DATA_WRITE_RETRY
                && s->early_data_state != tls_EARLY_DATA_FINISHED_WRITING)
            || s->session->ext.max_early_data > 0
            || s->psksession->ext.max_early_data == 0)
        memcpy(s->early_secret, s->psksession->early_secret, EVP_MAX_MD_SIZE);

    tls_SESSION_free(s->session);
    s->session = s->psksession;
    s->psksession = NULL;
    s->hit = 1;
    /* Early data is only allowed if we used the first ticket */
    if (identity != 0)
        s->ext.early_data_ok = 0;
#endif

    return 1;
}
