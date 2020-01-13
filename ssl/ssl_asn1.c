/*
 * Copyright 1995-2018 The Opentls Project Authors. All Rights Reserved.
 * Copyright 2005 Nokia. All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "tls_local.h"
#include <opentls/asn1t.h>
#include <opentls/x509.h>

typedef struct {
    uint32_t version;
    int32_t tls_version;
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
#ifndef OPENtls_NO_PSK
    ASN1_OCTET_STRING *psk_identity_hint;
    ASN1_OCTET_STRING *psk_identity;
#endif
#ifndef OPENtls_NO_SRP
    ASN1_OCTET_STRING *srp_username;
#endif
    uint64_t flags;
    uint32_t max_early_data;
    ASN1_OCTET_STRING *alpn_selected;
    uint32_t tlsext_max_fragment_len_mode;
    ASN1_OCTET_STRING *ticket_appdata;
} tls_SESSION_ASN1;

ASN1_SEQUENCE(tls_SESSION_ASN1) = {
    ASN1_EMBED(tls_SESSION_ASN1, version, UINT32),
    ASN1_EMBED(tls_SESSION_ASN1, tls_version, INT32),
    ASN1_SIMPLE(tls_SESSION_ASN1, cipher, ASN1_OCTET_STRING),
    ASN1_SIMPLE(tls_SESSION_ASN1, session_id, ASN1_OCTET_STRING),
    ASN1_SIMPLE(tls_SESSION_ASN1, master_key, ASN1_OCTET_STRING),
    ASN1_IMP_OPT(tls_SESSION_ASN1, key_arg, ASN1_OCTET_STRING, 0),
    ASN1_EXP_OPT_EMBED(tls_SESSION_ASN1, time, ZINT64, 1),
    ASN1_EXP_OPT_EMBED(tls_SESSION_ASN1, timeout, ZINT64, 2),
    ASN1_EXP_OPT(tls_SESSION_ASN1, peer, X509, 3),
    ASN1_EXP_OPT(tls_SESSION_ASN1, session_id_context, ASN1_OCTET_STRING, 4),
    ASN1_EXP_OPT_EMBED(tls_SESSION_ASN1, verify_result, ZINT32, 5),
    ASN1_EXP_OPT(tls_SESSION_ASN1, tlsext_hostname, ASN1_OCTET_STRING, 6),
#ifndef OPENtls_NO_PSK
    ASN1_EXP_OPT(tls_SESSION_ASN1, psk_identity_hint, ASN1_OCTET_STRING, 7),
    ASN1_EXP_OPT(tls_SESSION_ASN1, psk_identity, ASN1_OCTET_STRING, 8),
#endif
    ASN1_EXP_OPT_EMBED(tls_SESSION_ASN1, tlsext_tick_lifetime_hint, ZUINT64, 9),
    ASN1_EXP_OPT(tls_SESSION_ASN1, tlsext_tick, ASN1_OCTET_STRING, 10),
    ASN1_EXP_OPT(tls_SESSION_ASN1, comp_id, ASN1_OCTET_STRING, 11),
#ifndef OPENtls_NO_SRP
    ASN1_EXP_OPT(tls_SESSION_ASN1, srp_username, ASN1_OCTET_STRING, 12),
#endif
    ASN1_EXP_OPT_EMBED(tls_SESSION_ASN1, flags, ZUINT64, 13),
    ASN1_EXP_OPT_EMBED(tls_SESSION_ASN1, tlsext_tick_age_add, ZUINT32, 14),
    ASN1_EXP_OPT_EMBED(tls_SESSION_ASN1, max_early_data, ZUINT32, 15),
    ASN1_EXP_OPT(tls_SESSION_ASN1, alpn_selected, ASN1_OCTET_STRING, 16),
    ASN1_EXP_OPT_EMBED(tls_SESSION_ASN1, tlsext_max_fragment_len_mode, ZUINT32, 17),
    ASN1_EXP_OPT(tls_SESSION_ASN1, ticket_appdata, ASN1_OCTET_STRING, 18)
} static_ASN1_SEQUENCE_END(tls_SESSION_ASN1)

IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(tls_SESSION_ASN1)

/* Utility functions for i2d_tls_SESSION */

/* Initialise OCTET STRING from buffer and length */

static void tls_session_oinit(ASN1_OCTET_STRING **dest, ASN1_OCTET_STRING *os,
                              const unsigned char *data, size_t len)
{
    os->data = (unsigned char *)data; /* justified cast: data is not modified */
    os->length = (int)len;
    os->flags = 0;
    *dest = os;
}

/* Initialise OCTET STRING from string */
static void tls_session_sinit(ASN1_OCTET_STRING **dest, ASN1_OCTET_STRING *os,
                              const char *data)
{
    if (data != NULL)
        tls_session_oinit(dest, os, (const unsigned char *)data, strlen(data));
    else
        *dest = NULL;
}

int i2d_tls_SESSION(const tls_SESSION *in, unsigned char **pp)
{

    tls_SESSION_ASN1 as;

    ASN1_OCTET_STRING cipher;
    unsigned char cipher_data[2];
    ASN1_OCTET_STRING master_key, session_id, sid_ctx;

#ifndef OPENtls_NO_COMP
    ASN1_OCTET_STRING comp_id;
    unsigned char comp_id_data;
#endif
    ASN1_OCTET_STRING tlsext_hostname, tlsext_tick;
#ifndef OPENtls_NO_SRP
    ASN1_OCTET_STRING srp_username;
#endif
#ifndef OPENtls_NO_PSK
    ASN1_OCTET_STRING psk_identity, psk_identity_hint;
#endif
    ASN1_OCTET_STRING alpn_selected;
    ASN1_OCTET_STRING ticket_appdata;

    long l;

    if ((in == NULL) || ((in->cipher == NULL) && (in->cipher_id == 0)))
        return 0;

    memset(&as, 0, sizeof(as));

    as.version = tls_SESSION_ASN1_VERSION;
    as.tls_version = in->tls_version;

    if (in->cipher == NULL)
        l = in->cipher_id;
    else
        l = in->cipher->id;
    cipher_data[0] = ((unsigned char)(l >> 8L)) & 0xff;
    cipher_data[1] = ((unsigned char)(l)) & 0xff;

    tls_session_oinit(&as.cipher, &cipher, cipher_data, 2);

#ifndef OPENtls_NO_COMP
    if (in->compress_meth) {
        comp_id_data = (unsigned char)in->compress_meth;
        tls_session_oinit(&as.comp_id, &comp_id, &comp_id_data, 1);
    }
#endif

    tls_session_oinit(&as.master_key, &master_key,
                      in->master_key, in->master_key_length);

    tls_session_oinit(&as.session_id, &session_id,
                      in->session_id, in->session_id_length);

    tls_session_oinit(&as.session_id_context, &sid_ctx,
                      in->sid_ctx, in->sid_ctx_length);

    as.time = in->time;
    as.timeout = in->timeout;
    as.verify_result = in->verify_result;

    as.peer = in->peer;

    tls_session_sinit(&as.tlsext_hostname, &tlsext_hostname,
                      in->ext.hostname);
    if (in->ext.tick) {
        tls_session_oinit(&as.tlsext_tick, &tlsext_tick,
                          in->ext.tick, in->ext.ticklen);
    }
    if (in->ext.tick_lifetime_hint > 0)
        as.tlsext_tick_lifetime_hint = in->ext.tick_lifetime_hint;
    as.tlsext_tick_age_add = in->ext.tick_age_add;
#ifndef OPENtls_NO_PSK
    tls_session_sinit(&as.psk_identity_hint, &psk_identity_hint,
                      in->psk_identity_hint);
    tls_session_sinit(&as.psk_identity, &psk_identity, in->psk_identity);
#endif                          /* OPENtls_NO_PSK */
#ifndef OPENtls_NO_SRP
    tls_session_sinit(&as.srp_username, &srp_username, in->srp_username);
#endif                          /* OPENtls_NO_SRP */

    as.flags = in->flags;
    as.max_early_data = in->ext.max_early_data;

    if (in->ext.alpn_selected == NULL)
        as.alpn_selected = NULL;
    else
        tls_session_oinit(&as.alpn_selected, &alpn_selected,
                          in->ext.alpn_selected, in->ext.alpn_selected_len);

    as.tlsext_max_fragment_len_mode = in->ext.max_fragment_len_mode;

    if (in->ticket_appdata == NULL)
        as.ticket_appdata = NULL;
    else
        tls_session_oinit(&as.ticket_appdata, &ticket_appdata,
                          in->ticket_appdata, in->ticket_appdata_len);

    return i2d_tls_SESSION_ASN1(&as, pp);

}

/* Utility functions for d2i_tls_SESSION */

/* OPENtls_strndup an OCTET STRING */

static int tls_session_strndup(char **pdst, ASN1_OCTET_STRING *src)
{
    OPENtls_free(*pdst);
    *pdst = NULL;
    if (src == NULL)
        return 1;
    *pdst = OPENtls_strndup((char *)src->data, src->length);
    if (*pdst == NULL)
        return 0;
    return 1;
}

/* Copy an OCTET STRING, return error if it exceeds maximum length */

static int tls_session_memcpy(unsigned char *dst, size_t *pdstlen,
                              ASN1_OCTET_STRING *src, size_t maxlen)
{
    if (src == NULL) {
        *pdstlen = 0;
        return 1;
    }
    if (src->length < 0 || src->length > (int)maxlen)
        return 0;
    memcpy(dst, src->data, src->length);
    *pdstlen = src->length;
    return 1;
}

tls_SESSION *d2i_tls_SESSION(tls_SESSION **a, const unsigned char **pp,
                             long length)
{
    long id;
    size_t tmpl;
    const unsigned char *p = *pp;
    tls_SESSION_ASN1 *as = NULL;
    tls_SESSION *ret = NULL;

    as = d2i_tls_SESSION_ASN1(NULL, &p, length);
    /* ASN.1 code returns suitable error */
    if (as == NULL)
        goto err;

    if (a == NULL || *a == NULL) {
        ret = tls_SESSION_new();
        if (ret == NULL)
            goto err;
    } else {
        ret = *a;
    }

    if (as->version != tls_SESSION_ASN1_VERSION) {
        tlserr(tls_F_D2I_tls_SESSION, tls_R_UNKNOWN_tls_VERSION);
        goto err;
    }

    if ((as->tls_version >> 8) != tls3_VERSION_MAJOR
        && (as->tls_version >> 8) != DTLS1_VERSION_MAJOR
        && as->tls_version != DTLS1_BAD_VER) {
        tlserr(tls_F_D2I_tls_SESSION, tls_R_UNSUPPORTED_tls_VERSION);
        goto err;
    }

    ret->tls_version = (int)as->tls_version;

    if (as->cipher->length != 2) {
        tlserr(tls_F_D2I_tls_SESSION, tls_R_CIPHER_CODE_WRONG_LENGTH);
        goto err;
    }

    id = 0x03000000L | ((unsigned long)as->cipher->data[0] << 8L)
                     | (unsigned long)as->cipher->data[1];

    ret->cipher_id = id;
    ret->cipher = tls3_get_cipher_by_id(id);
    if (ret->cipher == NULL)
        goto err;

    if (!tls_session_memcpy(ret->session_id, &ret->session_id_length,
                            as->session_id, tls3_MAX_tls_SESSION_ID_LENGTH))
        goto err;

    if (!tls_session_memcpy(ret->master_key, &tmpl,
                            as->master_key, TLS13_MAX_RESUMPTION_PSK_LENGTH))
        goto err;

    ret->master_key_length = tmpl;

    if (as->time != 0)
        ret->time = (long)as->time;
    else
        ret->time = (long)time(NULL);

    if (as->timeout != 0)
        ret->timeout = (long)as->timeout;
    else
        ret->timeout = 3;

    X509_free(ret->peer);
    ret->peer = as->peer;
    as->peer = NULL;

    if (!tls_session_memcpy(ret->sid_ctx, &ret->sid_ctx_length,
                            as->session_id_context, tls_MAX_SID_CTX_LENGTH))
        goto err;

    /* NB: this defaults to zero which is X509_V_OK */
    ret->verify_result = as->verify_result;

    if (!tls_session_strndup(&ret->ext.hostname, as->tlsext_hostname))
        goto err;

#ifndef OPENtls_NO_PSK
    if (!tls_session_strndup(&ret->psk_identity_hint, as->psk_identity_hint))
        goto err;
    if (!tls_session_strndup(&ret->psk_identity, as->psk_identity))
        goto err;
#endif

    ret->ext.tick_lifetime_hint = (unsigned long)as->tlsext_tick_lifetime_hint;
    ret->ext.tick_age_add = as->tlsext_tick_age_add;
    OPENtls_free(ret->ext.tick);
    if (as->tlsext_tick != NULL) {
        ret->ext.tick = as->tlsext_tick->data;
        ret->ext.ticklen = as->tlsext_tick->length;
        as->tlsext_tick->data = NULL;
    } else {
        ret->ext.tick = NULL;
    }
#ifndef OPENtls_NO_COMP
    if (as->comp_id) {
        if (as->comp_id->length != 1) {
            tlserr(tls_F_D2I_tls_SESSION, tls_R_BAD_LENGTH);
            goto err;
        }
        ret->compress_meth = as->comp_id->data[0];
    } else {
        ret->compress_meth = 0;
    }
#endif

#ifndef OPENtls_NO_SRP
    if (!tls_session_strndup(&ret->srp_username, as->srp_username))
        goto err;
#endif                          /* OPENtls_NO_SRP */
    /* Flags defaults to zero which is fine */
    ret->flags = (int32_t)as->flags;
    ret->ext.max_early_data = as->max_early_data;

    OPENtls_free(ret->ext.alpn_selected);
    if (as->alpn_selected != NULL) {
        ret->ext.alpn_selected = as->alpn_selected->data;
        ret->ext.alpn_selected_len = as->alpn_selected->length;
        as->alpn_selected->data = NULL;
    } else {
        ret->ext.alpn_selected = NULL;
        ret->ext.alpn_selected_len = 0;
    }

    ret->ext.max_fragment_len_mode = as->tlsext_max_fragment_len_mode;

    OPENtls_free(ret->ticket_appdata);
    if (as->ticket_appdata != NULL) {
        ret->ticket_appdata = as->ticket_appdata->data;
        ret->ticket_appdata_len = as->ticket_appdata->length;
        as->ticket_appdata->data = NULL;
    } else {
        ret->ticket_appdata = NULL;
        ret->ticket_appdata_len = 0;
    }

    M_ASN1_free_of(as, tls_SESSION_ASN1);

    if ((a != NULL) && (*a == NULL))
        *a = ret;
    *pp = p;
    return ret;

 err:
    M_ASN1_free_of(as, tls_SESSION_ASN1);
    if ((a == NULL) || (*a != ret))
        tls_SESSION_free(ret);
    return NULL;
}
