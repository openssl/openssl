/*
 * Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2005 Nokia. All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "ssl_local.h"
#include <openssl/asn1t.h>
#include <crypto/asn1.h>
#include <openssl/encoder.h>
#include <openssl/x509.h>

typedef struct {
    uint32_t version;
    int32_t ssl_version;
    ASN1_OCTET_STRING *cipher;
    ASN1_OCTET_STRING *comp_id;
    ASN1_OCTET_STRING *master_key;
    ASN1_OCTET_STRING *session_id;
    ASN1_OCTET_STRING *key_arg;
    int64_t time;
    int64_t timeout;
    X509 *peer;
    ASN1_OCTET_STRING *session_id_context;
    int32_t verify_result;
    ASN1_OCTET_STRING *tlsext_hostname;
    uint64_t tlsext_tick_lifetime_hint;
    uint32_t tlsext_tick_age_add;
    ASN1_OCTET_STRING *tlsext_tick;
#ifndef OPENSSL_NO_PSK
    ASN1_OCTET_STRING *psk_identity_hint;
    ASN1_OCTET_STRING *psk_identity;
#endif
#ifndef OPENSSL_NO_SRP
    ASN1_OCTET_STRING *srp_username;
#endif
    uint64_t flags;
    uint32_t max_early_data;
    ASN1_OCTET_STRING *alpn_selected;
    uint32_t tlsext_max_fragment_len_mode;
    ASN1_OCTET_STRING *ticket_appdata;
    uint32_t kex_group;
    ASN1_OCTET_STRING *peer_rpk;
} SSL_SESSION_ASN1;

ASN1_SEQUENCE(SSL_SESSION_ASN1) = {
    ASN1_EMBED(SSL_SESSION_ASN1, version, UINT32),
    ASN1_EMBED(SSL_SESSION_ASN1, ssl_version, INT32),
    ASN1_SIMPLE(SSL_SESSION_ASN1, cipher, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SSL_SESSION_ASN1, session_id, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SSL_SESSION_ASN1, master_key, ASN1_OCTET_STRING),
    ASN1_IMP_OPT(SSL_SESSION_ASN1, key_arg, ASN1_OCTET_STRING, 0),
    ASN1_EXP_OPT_EMBED(SSL_SESSION_ASN1, time, ZINT64, 1),
    ASN1_EXP_OPT_EMBED(SSL_SESSION_ASN1, timeout, ZINT64, 2),
    ASN1_EXP_OPT(SSL_SESSION_ASN1, peer, X509, 3),
    ASN1_EXP_OPT(SSL_SESSION_ASN1, session_id_context, ASN1_OCTET_STRING, 4),
    ASN1_EXP_OPT_EMBED(SSL_SESSION_ASN1, verify_result, ZINT32, 5),
    ASN1_EXP_OPT(SSL_SESSION_ASN1, tlsext_hostname, ASN1_OCTET_STRING, 6),
#ifndef OPENSSL_NO_PSK
    ASN1_EXP_OPT(SSL_SESSION_ASN1, psk_identity_hint, ASN1_OCTET_STRING, 7),
    ASN1_EXP_OPT(SSL_SESSION_ASN1, psk_identity, ASN1_OCTET_STRING, 8),
#endif
    ASN1_EXP_OPT_EMBED(SSL_SESSION_ASN1, tlsext_tick_lifetime_hint, ZUINT64, 9),
    ASN1_EXP_OPT(SSL_SESSION_ASN1, tlsext_tick, ASN1_OCTET_STRING, 10),
    ASN1_EXP_OPT(SSL_SESSION_ASN1, comp_id, ASN1_OCTET_STRING, 11),
#ifndef OPENSSL_NO_SRP
    ASN1_EXP_OPT(SSL_SESSION_ASN1, srp_username, ASN1_OCTET_STRING, 12),
#endif
    ASN1_EXP_OPT_EMBED(SSL_SESSION_ASN1, flags, ZUINT64, 13),
    ASN1_EXP_OPT_EMBED(SSL_SESSION_ASN1, tlsext_tick_age_add, ZUINT32, 14),
    ASN1_EXP_OPT_EMBED(SSL_SESSION_ASN1, max_early_data, ZUINT32, 15),
    ASN1_EXP_OPT(SSL_SESSION_ASN1, alpn_selected, ASN1_OCTET_STRING, 16),
    ASN1_EXP_OPT_EMBED(SSL_SESSION_ASN1, tlsext_max_fragment_len_mode, ZUINT32, 17),
    ASN1_EXP_OPT(SSL_SESSION_ASN1, ticket_appdata, ASN1_OCTET_STRING, 18),
    ASN1_EXP_OPT_EMBED(SSL_SESSION_ASN1, kex_group, UINT32, 19),
    ASN1_EXP_OPT(SSL_SESSION_ASN1, peer_rpk, ASN1_OCTET_STRING, 20)
} static_ASN1_SEQUENCE_END(SSL_SESSION_ASN1)

IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(SSL_SESSION_ASN1)

/* Utility functions for i2d_SSL_SESSION */

/* Initialise OCTET STRING from buffer and length */

static int ssl_session_oinit(ASN1_OCTET_STRING **dest,
    const unsigned char *data, size_t len)
{
    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();

    if (os == NULL)
        return 0;
    if (!ASN1_OCTET_STRING_set(os, data, (int)len)) {
        ASN1_OCTET_STRING_free(os);
        return 0;
    }
    *dest = os;
    return 1;
}

/* Initialise OCTET STRING from string */
static int ssl_session_sinit(ASN1_OCTET_STRING **dest, const char *data)
{
    if (data != NULL)
        return ssl_session_oinit(dest, (const unsigned char *)data,
            strlen(data));
    *dest = NULL;
    return 1;
}

int i2d_SSL_SESSION(const SSL_SESSION *in, unsigned char **pp)
{

    SSL_SESSION_ASN1 as;
    unsigned char cipher_data[2];
#ifndef OPENSSL_NO_COMP
    unsigned char comp_id_data;
#endif
    long l;
    int ret = 0;

    if ((in == NULL) || ((in->cipher == NULL) && (in->cipher_id == 0)))
        return 0;

    memset(&as, 0, sizeof(as));

    as.version = SSL_SESSION_ASN1_VERSION;
    as.ssl_version = in->ssl_version;

    as.kex_group = in->kex_group;

    if (in->cipher == NULL)
        l = in->cipher_id;
    else
        l = in->cipher->id;
    cipher_data[0] = ((unsigned char)(l >> 8L)) & 0xff;
    cipher_data[1] = ((unsigned char)(l)) & 0xff;

    if (!ssl_session_oinit(&as.cipher, cipher_data, 2))
        goto err;

#ifndef OPENSSL_NO_COMP
    if (in->compress_meth) {
        comp_id_data = (unsigned char)in->compress_meth;
        if (!ssl_session_oinit(&as.comp_id, &comp_id_data, 1))
            goto err;
    }
#endif

    if (!ssl_session_oinit(&as.master_key,
            in->master_key, in->master_key_length))
        goto err;

    if (!ssl_session_oinit(&as.session_id,
            in->session_id, in->session_id_length))
        goto err;

    if (!ssl_session_oinit(&as.session_id_context,
            in->sid_ctx, in->sid_ctx_length))
        goto err;

    as.time = (int64_t)ossl_time_to_time_t(in->time);
    as.timeout = (int64_t)ossl_time2seconds(in->timeout);
    as.verify_result = in->verify_result;

    as.peer = in->peer;

    as.peer_rpk = NULL;
    if (in->peer_rpk != NULL) {
        unsigned char *rpkdata = NULL;
        int rpklen = i2d_PUBKEY(in->peer_rpk, &rpkdata);
        if (rpklen > 0 && rpkdata != NULL) {
            as.peer_rpk = ASN1_OCTET_STRING_new();
            if (as.peer_rpk == NULL) {
                OPENSSL_free(rpkdata);
                goto err;
            }
            ASN1_STRING_set0(as.peer_rpk, rpkdata, rpklen);
        }
    }

    if (!ssl_session_sinit(&as.tlsext_hostname, in->ext.hostname))
        goto err;
    if (in->ext.tick) {
        if (!ssl_session_oinit(&as.tlsext_tick,
                in->ext.tick, in->ext.ticklen))
            goto err;
    }
    if (in->ext.tick_lifetime_hint > 0)
        as.tlsext_tick_lifetime_hint = in->ext.tick_lifetime_hint;
    as.tlsext_tick_age_add = in->ext.tick_age_add;
#ifndef OPENSSL_NO_PSK
    if (!ssl_session_sinit(&as.psk_identity_hint, in->psk_identity_hint))
        goto err;
    if (!ssl_session_sinit(&as.psk_identity, in->psk_identity))
        goto err;
#endif /* OPENSSL_NO_PSK */
#ifndef OPENSSL_NO_SRP
    if (!ssl_session_sinit(&as.srp_username, in->srp_username))
        goto err;
#endif /* OPENSSL_NO_SRP */

    as.flags = in->flags;
    as.max_early_data = in->ext.max_early_data;

    if (in->ext.alpn_selected != NULL) {
        if (!ssl_session_oinit(&as.alpn_selected,
                in->ext.alpn_selected, in->ext.alpn_selected_len))
            goto err;
    }

    as.tlsext_max_fragment_len_mode = in->ext.max_fragment_len_mode;

    if (in->ticket_appdata != NULL) {
        if (!ssl_session_oinit(&as.ticket_appdata,
                in->ticket_appdata, in->ticket_appdata_len))
            goto err;
    }

    ret = i2d_SSL_SESSION_ASN1(&as, pp);
    goto cleanup;
err:
    ret = 0;
cleanup:
    ASN1_OCTET_STRING_free(as.cipher);
    ASN1_OCTET_STRING_free(as.master_key);
    ASN1_OCTET_STRING_free(as.session_id);
    ASN1_OCTET_STRING_free(as.session_id_context);
#ifndef OPENSSL_NO_COMP
    ASN1_OCTET_STRING_free(as.comp_id);
#endif
    ASN1_OCTET_STRING_free(as.tlsext_hostname);
    ASN1_OCTET_STRING_free(as.tlsext_tick);
#ifndef OPENSSL_NO_SRP
    ASN1_OCTET_STRING_free(as.srp_username);
#endif
#ifndef OPENSSL_NO_PSK
    ASN1_OCTET_STRING_free(as.psk_identity_hint);
    ASN1_OCTET_STRING_free(as.psk_identity);
#endif
    ASN1_OCTET_STRING_free(as.alpn_selected);
    ASN1_OCTET_STRING_free(as.ticket_appdata);
    ASN1_OCTET_STRING_free(as.peer_rpk);
    return ret;
}

/* Utility functions for d2i_SSL_SESSION */

/* OPENSSL_strndup an OCTET STRING */

static int ssl_session_strndup(char **pdst, ASN1_OCTET_STRING *src)
{
    OPENSSL_free(*pdst);
    *pdst = NULL;
    if (src == NULL)
        return 1;
    *pdst = OPENSSL_strndup((char *)ASN1_STRING_get0_data(src), ASN1_STRING_length(src));
    if (*pdst == NULL)
        return 0;
    return 1;
}

/* Copy an OCTET STRING, return error if it exceeds maximum length */

static int ssl_session_memcpy(unsigned char *dst, size_t *pdstlen,
    ASN1_OCTET_STRING *src, size_t maxlen)
{
    if (src == NULL || ASN1_STRING_length(src) == 0) {
        *pdstlen = 0;
        return 1;
    }
    if (ASN1_STRING_length(src) < 0 || ASN1_STRING_length(src) > (int)maxlen)
        return 0;
    memcpy(dst, ASN1_STRING_get0_data(src), ASN1_STRING_length(src));
    *pdstlen = ASN1_STRING_length(src);
    return 1;
}

SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp,
    long length)
{
    return d2i_SSL_SESSION_ex(a, pp, length, NULL, NULL);
}
SSL_SESSION *d2i_SSL_SESSION_ex(SSL_SESSION **a, const unsigned char **pp,
    long length, OSSL_LIB_CTX *libctx,
    const char *propq)
{
    long id;
    size_t tmpl;
    const unsigned char *p = *pp;
    SSL_SESSION_ASN1 *as = NULL;
    SSL_SESSION *ret = NULL;

    as = d2i_SSL_SESSION_ASN1(NULL, &p, length);
    /* ASN.1 code returns suitable error */
    if (as == NULL)
        goto err;

    if (a == NULL || *a == NULL) {
        ret = SSL_SESSION_new();
        if (ret == NULL)
            goto err;
    } else {
        ret = *a;
    }

    if (as->version != SSL_SESSION_ASN1_VERSION) {
        ERR_raise(ERR_LIB_SSL, SSL_R_UNKNOWN_SSL_VERSION);
        goto err;
    }

    if ((as->ssl_version >> 8) != SSL3_VERSION_MAJOR
        && (as->ssl_version >> 8) != DTLS1_VERSION_MAJOR
        && as->ssl_version != DTLS1_BAD_VER) {
        ERR_raise(ERR_LIB_SSL, SSL_R_UNSUPPORTED_SSL_VERSION);
        goto err;
    }

    ret->ssl_version = (int)as->ssl_version;

    ret->kex_group = as->kex_group;

    if (ASN1_STRING_length(as->cipher) != 2) {
        ERR_raise(ERR_LIB_SSL, SSL_R_CIPHER_CODE_WRONG_LENGTH);
        goto err;
    }

    id = 0x03000000L | ((unsigned long)ASN1_STRING_get0_data(as->cipher)[0] << 8L)
        | (unsigned long)ASN1_STRING_get0_data(as->cipher)[1];

    ret->cipher_id = id;
    ret->cipher = ssl3_get_cipher_by_id(id);
    if (ret->cipher == NULL)
        goto err;

    if (!ssl_session_memcpy(ret->session_id, &ret->session_id_length,
            as->session_id, SSL3_MAX_SSL_SESSION_ID_LENGTH))
        goto err;

    if (!ssl_session_memcpy(ret->master_key, &tmpl,
            as->master_key, TLS13_MAX_RESUMPTION_PSK_LENGTH))
        goto err;

    ret->master_key_length = tmpl;

    if (as->time != 0)
        ret->time = ossl_time_from_time_t(as->time);
    else
        ret->time = ossl_time_now();

    if (as->timeout != 0)
        ret->timeout = ossl_seconds2time(as->timeout);
    else
        ret->timeout = ossl_seconds2time(3);
    ssl_session_calculate_timeout(ret);

    X509_free(ret->peer);
    ret->peer = as->peer;
    as->peer = NULL;

    EVP_PKEY_free(ret->peer_rpk);
    ret->peer_rpk = NULL;
    if (as->peer_rpk != NULL) {
        const unsigned char *data = ASN1_STRING_get0_data(as->peer_rpk);

        /*
         * |data| is incremented; we don't want to lose original ptr
         */
        ret->peer_rpk = d2i_PUBKEY_ex(NULL, &data, ASN1_STRING_length(as->peer_rpk), libctx, propq);
        if (ret->peer_rpk == NULL)
            goto err;
    }

    if (!ssl_session_memcpy(ret->sid_ctx, &ret->sid_ctx_length,
            as->session_id_context, SSL_MAX_SID_CTX_LENGTH))
        goto err;

    /* NB: this defaults to zero which is X509_V_OK */
    ret->verify_result = as->verify_result;

    if (!ssl_session_strndup(&ret->ext.hostname, as->tlsext_hostname))
        goto err;

#ifndef OPENSSL_NO_PSK
    if (!ssl_session_strndup(&ret->psk_identity_hint, as->psk_identity_hint))
        goto err;
    if (!ssl_session_strndup(&ret->psk_identity, as->psk_identity))
        goto err;
#endif

    ret->ext.tick_lifetime_hint = (unsigned long)as->tlsext_tick_lifetime_hint;
    ret->ext.tick_age_add = as->tlsext_tick_age_add;
    OPENSSL_free(ret->ext.tick);
    if (as->tlsext_tick != NULL) {
        ret->ext.tick = as->tlsext_tick->data;
        ret->ext.ticklen = as->tlsext_tick->length;
        as->tlsext_tick->data = NULL;
    } else {
        ret->ext.tick = NULL;
    }
#ifndef OPENSSL_NO_COMP
    if (as->comp_id) {
        if (ASN1_STRING_length(as->comp_id) != 1) {
            ERR_raise(ERR_LIB_SSL, SSL_R_BAD_LENGTH);
            goto err;
        }
        ret->compress_meth = ASN1_STRING_get0_data(as->comp_id)[0];
    } else {
        ret->compress_meth = 0;
    }
#endif

#ifndef OPENSSL_NO_SRP
    if (!ssl_session_strndup(&ret->srp_username, as->srp_username))
        goto err;
#endif /* OPENSSL_NO_SRP */
    /* Flags defaults to zero which is fine */
    ret->flags = (int32_t)as->flags;
    ret->ext.max_early_data = as->max_early_data;

    OPENSSL_free(ret->ext.alpn_selected);
    if (as->alpn_selected != NULL) {
        ret->ext.alpn_selected = as->alpn_selected->data;
        ret->ext.alpn_selected_len = as->alpn_selected->length;
        as->alpn_selected->data = NULL;
    } else {
        ret->ext.alpn_selected = NULL;
        ret->ext.alpn_selected_len = 0;
    }

    ret->ext.max_fragment_len_mode = as->tlsext_max_fragment_len_mode;

    OPENSSL_free(ret->ticket_appdata);
    if (as->ticket_appdata != NULL) {
        ret->ticket_appdata = as->ticket_appdata->data;
        ret->ticket_appdata_len = as->ticket_appdata->length;
        as->ticket_appdata->data = NULL;
    } else {
        ret->ticket_appdata = NULL;
        ret->ticket_appdata_len = 0;
    }

    M_ASN1_free_of(as, SSL_SESSION_ASN1);

    if ((a != NULL) && (*a == NULL))
        *a = ret;
    *pp = p;
    return ret;

err:
    M_ASN1_free_of(as, SSL_SESSION_ASN1);
    if ((a == NULL) || (*a != ret))
        SSL_SESSION_free(ret);
    return NULL;
}
