/*
 * Copyright 1995-2018 The Opentls Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 * Copyright 2005 Nokia. All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include "tls_local.h"
#include "e_os.h"
#include <opentls/objects.h>
#include <opentls/x509v3.h>
#include <opentls/rand.h>
#include <opentls/rand_drbg.h>
#include <opentls/ocsp.h>
#include <opentls/dh.h>
#include <opentls/engine.h>
#include <opentls/async.h>
#include <opentls/ct.h>
#include <opentls/trace.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"
#include "internal/ktls.h"

static int tls_undefined_function_1(tls *tls, tls3_RECORD *r, size_t s, int t)
{
    (void)r;
    (void)s;
    (void)t;
    return tls_undefined_function(tls);
}

static int tls_undefined_function_2(tls *tls, tls3_RECORD *r, unsigned char *s,
                                    int t)
{
    (void)r;
    (void)s;
    (void)t;
    return tls_undefined_function(tls);
}

static int tls_undefined_function_3(tls *tls, unsigned char *r,
                                    unsigned char *s, size_t t, size_t *u)
{
    (void)r;
    (void)s;
    (void)t;
    (void)u;
    return tls_undefined_function(tls);
}

static int tls_undefined_function_4(tls *tls, int r)
{
    (void)r;
    return tls_undefined_function(tls);
}

static size_t tls_undefined_function_5(tls *tls, const char *r, size_t s,
                                       unsigned char *t)
{
    (void)r;
    (void)s;
    (void)t;
    return tls_undefined_function(tls);
}

static int tls_undefined_function_6(int r)
{
    (void)r;
    return tls_undefined_function(NULL);
}

static int tls_undefined_function_7(tls *tls, unsigned char *r, size_t s,
                                    const char *t, size_t u,
                                    const unsigned char *v, size_t w, int x)
{
    (void)r;
    (void)s;
    (void)t;
    (void)u;
    (void)v;
    (void)w;
    (void)x;
    return tls_undefined_function(tls);
}

tls3_ENC_METHOD tls3_undef_enc_method = {
    tls_undefined_function_1,
    tls_undefined_function_2,
    tls_undefined_function,
    tls_undefined_function_3,
    tls_undefined_function_4,
    tls_undefined_function_5,
    NULL,                       /* client_finished_label */
    0,                          /* client_finished_label_len */
    NULL,                       /* server_finished_label */
    0,                          /* server_finished_label_len */
    tls_undefined_function_6,
    tls_undefined_function_7,
};

struct tls_async_args {
    tls *s;
    void *buf;
    size_t num;
    enum { READFUNC, WRITEFUNC, OTHERFUNC } type;
    union {
        int (*func_read) (tls *, void *, size_t, size_t *);
        int (*func_write) (tls *, const void *, size_t, size_t *);
        int (*func_other) (tls *);
    } f;
};

static const struct {
    uint8_t mtype;
    uint8_t ord;
    int nid;
} dane_mds[] = {
    {
        DANETLS_MATCHING_FULL, 0, NID_undef
    },
    {
        DANETLS_MATCHING_2256, 1, NID_sha256
    },
    {
        DANETLS_MATCHING_2512, 2, NID_sha512
    },
};

static int dane_ctx_enable(struct dane_ctx_st *dctx)
{
    const EVP_MD **mdevp;
    uint8_t *mdord;
    uint8_t mdmax = DANETLS_MATCHING_LAST;
    int n = ((int)mdmax) + 1;   /* int to handle PrivMatch(255) */
    size_t i;

    if (dctx->mdevp != NULL)
        return 1;

    mdevp = OPENtls_zalloc(n * sizeof(*mdevp));
    mdord = OPENtls_zalloc(n * sizeof(*mdord));

    if (mdord == NULL || mdevp == NULL) {
        OPENtls_free(mdord);
        OPENtls_free(mdevp);
        tlserr(tls_F_DANE_CTX_ENABLE, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /* Install default entries */
    for (i = 0; i < Otls_NELEM(dane_mds); ++i) {
        const EVP_MD *md;

        if (dane_mds[i].nid == NID_undef ||
            (md = EVP_get_digestbynid(dane_mds[i].nid)) == NULL)
            continue;
        mdevp[dane_mds[i].mtype] = md;
        mdord[dane_mds[i].mtype] = dane_mds[i].ord;
    }

    dctx->mdevp = mdevp;
    dctx->mdord = mdord;
    dctx->mdmax = mdmax;

    return 1;
}

static void dane_ctx_final(struct dane_ctx_st *dctx)
{
    OPENtls_free(dctx->mdevp);
    dctx->mdevp = NULL;

    OPENtls_free(dctx->mdord);
    dctx->mdord = NULL;
    dctx->mdmax = 0;
}

static void tlsa_free(danetls_record *t)
{
    if (t == NULL)
        return;
    OPENtls_free(t->data);
    EVP_PKEY_free(t->spki);
    OPENtls_free(t);
}

static void dane_final(tls_DANE *dane)
{
    sk_danetls_record_pop_free(dane->trecs, tlsa_free);
    dane->trecs = NULL;

    sk_X509_pop_free(dane->certs, X509_free);
    dane->certs = NULL;

    X509_free(dane->mcert);
    dane->mcert = NULL;
    dane->mtlsa = NULL;
    dane->mdpth = -1;
    dane->pdpth = -1;
}

/*
 * dane_copy - Copy dane configuration, sans verification state.
 */
static int tls_dane_dup(tls *to, tls *from)
{
    int num;
    int i;

    if (!DANETLS_ENABLED(&from->dane))
        return 1;

    num = sk_danetls_record_num(from->dane.trecs);
    dane_final(&to->dane);
    to->dane.flags = from->dane.flags;
    to->dane.dctx = &to->ctx->dane;
    to->dane.trecs = sk_danetls_record_new_reserve(NULL, num);

    if (to->dane.trecs == NULL) {
        tlserr(tls_F_tls_DANE_DUP, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    for (i = 0; i < num; ++i) {
        danetls_record *t = sk_danetls_record_value(from->dane.trecs, i);

        if (tls_dane_tlsa_add(to, t->usage, t->selector, t->mtype,
                              t->data, t->dlen) <= 0)
            return 0;
    }
    return 1;
}

static int dane_mtype_set(struct dane_ctx_st *dctx,
                          const EVP_MD *md, uint8_t mtype, uint8_t ord)
{
    int i;

    if (mtype == DANETLS_MATCHING_FULL && md != NULL) {
        tlserr(tls_F_DANE_MTYPE_SET, tls_R_DANE_CANNOT_OVERRIDE_MTYPE_FULL);
        return 0;
    }

    if (mtype > dctx->mdmax) {
        const EVP_MD **mdevp;
        uint8_t *mdord;
        int n = ((int)mtype) + 1;

        mdevp = OPENtls_realloc(dctx->mdevp, n * sizeof(*mdevp));
        if (mdevp == NULL) {
            tlserr(tls_F_DANE_MTYPE_SET, ERR_R_MALLOC_FAILURE);
            return -1;
        }
        dctx->mdevp = mdevp;

        mdord = OPENtls_realloc(dctx->mdord, n * sizeof(*mdord));
        if (mdord == NULL) {
            tlserr(tls_F_DANE_MTYPE_SET, ERR_R_MALLOC_FAILURE);
            return -1;
        }
        dctx->mdord = mdord;

        /* Zero-fill any gaps */
        for (i = dctx->mdmax + 1; i < mtype; ++i) {
            mdevp[i] = NULL;
            mdord[i] = 0;
        }

        dctx->mdmax = mtype;
    }

    dctx->mdevp[mtype] = md;
    /* Coerce ordinal of disabled matching types to 0 */
    dctx->mdord[mtype] = (md == NULL) ? 0 : ord;

    return 1;
}

static const EVP_MD *tlsa_md_get(tls_DANE *dane, uint8_t mtype)
{
    if (mtype > dane->dctx->mdmax)
        return NULL;
    return dane->dctx->mdevp[mtype];
}

static int dane_tlsa_add(tls_DANE *dane,
                         uint8_t usage,
                         uint8_t selector,
                         uint8_t mtype, unsigned const char *data, size_t dlen)
{
    danetls_record *t;
    const EVP_MD *md = NULL;
    int ilen = (int)dlen;
    int i;
    int num;

    if (dane->trecs == NULL) {
        tlserr(tls_F_DANE_TLSA_ADD, tls_R_DANE_NOT_ENABLED);
        return -1;
    }

    if (ilen < 0 || dlen != (size_t)ilen) {
        tlserr(tls_F_DANE_TLSA_ADD, tls_R_DANE_TLSA_BAD_DATA_LENGTH);
        return 0;
    }

    if (usage > DANETLS_USAGE_LAST) {
        tlserr(tls_F_DANE_TLSA_ADD, tls_R_DANE_TLSA_BAD_CERTIFICATE_USAGE);
        return 0;
    }

    if (selector > DANETLS_SELECTOR_LAST) {
        tlserr(tls_F_DANE_TLSA_ADD, tls_R_DANE_TLSA_BAD_SELECTOR);
        return 0;
    }

    if (mtype != DANETLS_MATCHING_FULL) {
        md = tlsa_md_get(dane, mtype);
        if (md == NULL) {
            tlserr(tls_F_DANE_TLSA_ADD, tls_R_DANE_TLSA_BAD_MATCHING_TYPE);
            return 0;
        }
    }

    if (md != NULL && dlen != (size_t)EVP_MD_size(md)) {
        tlserr(tls_F_DANE_TLSA_ADD, tls_R_DANE_TLSA_BAD_DIGEST_LENGTH);
        return 0;
    }
    if (!data) {
        tlserr(tls_F_DANE_TLSA_ADD, tls_R_DANE_TLSA_NULL_DATA);
        return 0;
    }

    if ((t = OPENtls_zalloc(sizeof(*t))) == NULL) {
        tlserr(tls_F_DANE_TLSA_ADD, ERR_R_MALLOC_FAILURE);
        return -1;
    }

    t->usage = usage;
    t->selector = selector;
    t->mtype = mtype;
    t->data = OPENtls_malloc(dlen);
    if (t->data == NULL) {
        tlsa_free(t);
        tlserr(tls_F_DANE_TLSA_ADD, ERR_R_MALLOC_FAILURE);
        return -1;
    }
    memcpy(t->data, data, dlen);
    t->dlen = dlen;

    /* Validate and cache full certificate or public key */
    if (mtype == DANETLS_MATCHING_FULL) {
        const unsigned char *p = data;
        X509 *cert = NULL;
        EVP_PKEY *pkey = NULL;

        switch (selector) {
        case DANETLS_SELECTOR_CERT:
            if (!d2i_X509(&cert, &p, ilen) || p < data ||
                dlen != (size_t)(p - data)) {
                tlsa_free(t);
                tlserr(tls_F_DANE_TLSA_ADD, tls_R_DANE_TLSA_BAD_CERTIFICATE);
                return 0;
            }
            if (X509_get0_pubkey(cert) == NULL) {
                tlsa_free(t);
                tlserr(tls_F_DANE_TLSA_ADD, tls_R_DANE_TLSA_BAD_CERTIFICATE);
                return 0;
            }

            if ((DANETLS_USAGE_BIT(usage) & DANETLS_TA_MASK) == 0) {
                X509_free(cert);
                break;
            }

            /*
             * For usage DANE-TA(2), we support authentication via "2 0 0" TLSA
             * records that contain full certificates of trust-anchors that are
             * not present in the wire chain.  For usage PKIX-TA(0), we augment
             * the chain with untrusted Full(0) certificates from DNS, in case
             * they are missing from the chain.
             */
            if ((dane->certs == NULL &&
                 (dane->certs = sk_X509_new_null()) == NULL) ||
                !sk_X509_push(dane->certs, cert)) {
                tlserr(tls_F_DANE_TLSA_ADD, ERR_R_MALLOC_FAILURE);
                X509_free(cert);
                tlsa_free(t);
                return -1;
            }
            break;

        case DANETLS_SELECTOR_SPKI:
            if (!d2i_PUBKEY(&pkey, &p, ilen) || p < data ||
                dlen != (size_t)(p - data)) {
                tlsa_free(t);
                tlserr(tls_F_DANE_TLSA_ADD, tls_R_DANE_TLSA_BAD_PUBLIC_KEY);
                return 0;
            }

            /*
             * For usage DANE-TA(2), we support authentication via "2 1 0" TLSA
             * records that contain full bare keys of trust-anchors that are
             * not present in the wire chain.
             */
            if (usage == DANETLS_USAGE_DANE_TA)
                t->spki = pkey;
            else
                EVP_PKEY_free(pkey);
            break;
        }
    }

    /*-
     * Find the right insertion point for the new record.
     *
     * See crypto/x509/x509_vfy.c.  We sort DANE-EE(3) records first, so that
     * they can be processed first, as they require no chain building, and no
     * expiration or hostname checks.  Because DANE-EE(3) is numerically
     * largest, this is accomplished via descending sort by "usage".
     *
     * We also sort in descending order by matching ordinal to simplify
     * the implementation of digest agility in the verification code.
     *
     * The choice of order for the selector is not significant, so we
     * use the same descending order for consistency.
     */
    num = sk_danetls_record_num(dane->trecs);
    for (i = 0; i < num; ++i) {
        danetls_record *rec = sk_danetls_record_value(dane->trecs, i);

        if (rec->usage > usage)
            continue;
        if (rec->usage < usage)
            break;
        if (rec->selector > selector)
            continue;
        if (rec->selector < selector)
            break;
        if (dane->dctx->mdord[rec->mtype] > dane->dctx->mdord[mtype])
            continue;
        break;
    }

    if (!sk_danetls_record_insert(dane->trecs, t, i)) {
        tlsa_free(t);
        tlserr(tls_F_DANE_TLSA_ADD, ERR_R_MALLOC_FAILURE);
        return -1;
    }
    dane->umask |= DANETLS_USAGE_BIT(usage);

    return 1;
}

/*
 * Return 0 if there is only one version configured and it was disabled
 * at configure time.  Return 1 otherwise.
 */
static int tls_check_allowed_versions(int min_version, int max_version)
{
    int minisdtls = 0, maxisdtls = 0;

    /* Figure out if we're doing DTLS versions or TLS versions */
    if (min_version == DTLS1_BAD_VER
        || min_version >> 8 == DTLS1_VERSION_MAJOR)
        minisdtls = 1;
    if (max_version == DTLS1_BAD_VER
        || max_version >> 8 == DTLS1_VERSION_MAJOR)
        maxisdtls = 1;
    /* A wildcard version of 0 could be DTLS or TLS. */
    if ((minisdtls && !maxisdtls && max_version != 0)
        || (maxisdtls && !minisdtls && min_version != 0)) {
        /* Mixing DTLS and TLS versions will lead to sadness; deny it. */
        return 0;
    }

    if (minisdtls || maxisdtls) {
        /* Do DTLS version checks. */
        if (min_version == 0)
            /* Ignore DTLS1_BAD_VER */
            min_version = DTLS1_VERSION;
        if (max_version == 0)
            max_version = DTLS1_2_VERSION;
#ifdef OPENtls_NO_DTLS1_2
        if (max_version == DTLS1_2_VERSION)
            max_version = DTLS1_VERSION;
#endif
#ifdef OPENtls_NO_DTLS1
        if (min_version == DTLS1_VERSION)
            min_version = DTLS1_2_VERSION;
#endif
        /* Done massaging versions; do the check. */
        if (0
#ifdef OPENtls_NO_DTLS1
            || (DTLS_VERSION_GE(min_version, DTLS1_VERSION)
                && DTLS_VERSION_GE(DTLS1_VERSION, max_version))
#endif
#ifdef OPENtls_NO_DTLS1_2
            || (DTLS_VERSION_GE(min_version, DTLS1_2_VERSION)
                && DTLS_VERSION_GE(DTLS1_2_VERSION, max_version))
#endif
            )
            return 0;
    } else {
        /* Regular TLS version checks. */
        if (min_version == 0)
            min_version = tls3_VERSION;
        if (max_version == 0)
            max_version = TLS1_3_VERSION;
#ifdef OPENtls_NO_TLS1_3
        if (max_version == TLS1_3_VERSION)
            max_version = TLS1_2_VERSION;
#endif
#ifdef OPENtls_NO_TLS1_2
        if (max_version == TLS1_2_VERSION)
            max_version = TLS1_1_VERSION;
#endif
#ifdef OPENtls_NO_TLS1_1
        if (max_version == TLS1_1_VERSION)
            max_version = TLS1_VERSION;
#endif
#ifdef OPENtls_NO_TLS1
        if (max_version == TLS1_VERSION)
            max_version = tls3_VERSION;
#endif
#ifdef OPENtls_NO_tls3
        if (min_version == tls3_VERSION)
            min_version = TLS1_VERSION;
#endif
#ifdef OPENtls_NO_TLS1
        if (min_version == TLS1_VERSION)
            min_version = TLS1_1_VERSION;
#endif
#ifdef OPENtls_NO_TLS1_1
        if (min_version == TLS1_1_VERSION)
            min_version = TLS1_2_VERSION;
#endif
#ifdef OPENtls_NO_TLS1_2
        if (min_version == TLS1_2_VERSION)
            min_version = TLS1_3_VERSION;
#endif
        /* Done massaging versions; do the check. */
        if (0
#ifdef OPENtls_NO_tls3
            || (min_version <= tls3_VERSION && tls3_VERSION <= max_version)
#endif
#ifdef OPENtls_NO_TLS1
            || (min_version <= TLS1_VERSION && TLS1_VERSION <= max_version)
#endif
#ifdef OPENtls_NO_TLS1_1
            || (min_version <= TLS1_1_VERSION && TLS1_1_VERSION <= max_version)
#endif
#ifdef OPENtls_NO_TLS1_2
            || (min_version <= TLS1_2_VERSION && TLS1_2_VERSION <= max_version)
#endif
#ifdef OPENtls_NO_TLS1_3
            || (min_version <= TLS1_3_VERSION && TLS1_3_VERSION <= max_version)
#endif
            )
            return 0;
    }
    return 1;
}

static void clear_ciphers(tls *s)
{
    /* clear the current cipher */
    tls_clear_cipher_ctx(s);
    tls_clear_hash_ctx(&s->read_hash);
    tls_clear_hash_ctx(&s->write_hash);
}

int tls_clear(tls *s)
{
    if (s->method == NULL) {
        tlserr(tls_F_tls_CLEAR, tls_R_NO_METHOD_SPECIFIED);
        return 0;
    }

    if (tls_clear_bad_session(s)) {
        tls_SESSION_free(s->session);
        s->session = NULL;
    }
    tls_SESSION_free(s->psksession);
    s->psksession = NULL;
    OPENtls_free(s->psksession_id);
    s->psksession_id = NULL;
    s->psksession_id_len = 0;
    s->hello_retry_request = 0;
    s->sent_tickets = 0;

    s->error = 0;
    s->hit = 0;
    s->shutdown = 0;

    if (s->renegotiate) {
        tlserr(tls_F_tls_CLEAR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    otls_statem_clear(s);

    s->version = s->method->version;
    s->client_version = s->version;
    s->rwstate = tls_NOTHING;

    BUF_MEM_free(s->init_buf);
    s->init_buf = NULL;
    clear_ciphers(s);
    s->first_packet = 0;

    s->key_update = tls_KEY_UPDATE_NONE;

    EVP_MD_CTX_free(s->pha_dgst);
    s->pha_dgst = NULL;

    /* Reset DANE verification result state */
    s->dane.mdpth = -1;
    s->dane.pdpth = -1;
    X509_free(s->dane.mcert);
    s->dane.mcert = NULL;
    s->dane.mtlsa = NULL;

    /* Clear the verification result peername */
    X509_VERIFY_PARAM_move_peername(s->param, NULL);

    /* Clear any shared connection state */
    OPENtls_free(s->shared_sigalgs);
    s->shared_sigalgs = NULL;
    s->shared_sigalgslen = 0;

    /*
     * Check to see if we were changed into a different method, if so, revert
     * back.
     */
    if (s->method != s->ctx->method) {
        s->method->tls_free(s);
        s->method = s->ctx->method;
        if (!s->method->tls_new(s))
            return 0;
    } else {
        if (!s->method->tls_clear(s))
            return 0;
    }

    RECORD_LAYER_clear(&s->rlayer);

    return 1;
}

/** Used to change an tls_CTXs default tls method type */
int tls_CTX_set_tls_version(tls_CTX *ctx, const tls_METHOD *meth)
{
    STACK_OF(tls_CIPHER) *sk;

    ctx->method = meth;

    if (!tls_CTX_set_ciphersuites(ctx, Otls_default_ciphersuites())) {
        tlserr(tls_F_tls_CTX_SET_tls_VERSION, tls_R_tls_LIBRARY_HAS_NO_CIPHERS);
        return 0;
    }
    sk = tls_create_cipher_list(ctx->method,
                                ctx->tls13_ciphersuites,
                                &(ctx->cipher_list),
                                &(ctx->cipher_list_by_id),
                                Otls_default_cipher_list(), ctx->cert);
    if ((sk == NULL) || (sk_tls_CIPHER_num(sk) <= 0)) {
        tlserr(tls_F_tls_CTX_SET_tls_VERSION, tls_R_tls_LIBRARY_HAS_NO_CIPHERS);
        return 0;
    }
    return 1;
}

tls *tls_new(tls_CTX *ctx)
{
    tls *s;

    if (ctx == NULL) {
        tlserr(tls_F_tls_NEW, tls_R_NULL_tls_CTX);
        return NULL;
    }
    if (ctx->method == NULL) {
        tlserr(tls_F_tls_NEW, tls_R_tls_CTX_HAS_NO_DEFAULT_tls_VERSION);
        return NULL;
    }

    s = OPENtls_zalloc(sizeof(*s));
    if (s == NULL)
        goto err;

    s->references = 1;
    s->lock = CRYPTO_THREAD_lock_new();
    if (s->lock == NULL) {
        OPENtls_free(s);
        s = NULL;
        goto err;
    }

    RECORD_LAYER_init(&s->rlayer, s);

    s->options = ctx->options;
    s->dane.flags = ctx->dane.flags;
    s->min_proto_version = ctx->min_proto_version;
    s->max_proto_version = ctx->max_proto_version;
    s->mode = ctx->mode;
    s->max_cert_list = ctx->max_cert_list;
    s->max_early_data = ctx->max_early_data;
    s->recv_max_early_data = ctx->recv_max_early_data;
    s->num_tickets = ctx->num_tickets;
    s->pha_enabled = ctx->pha_enabled;

    /* Shallow copy of the ciphersuites stack */
    s->tls13_ciphersuites = sk_tls_CIPHER_dup(ctx->tls13_ciphersuites);
    if (s->tls13_ciphersuites == NULL)
        goto err;

    /*
     * Earlier library versions used to copy the pointer to the CERT, not
     * its contents; only when setting new parameters for the per-tls
     * copy, tls_cert_new would be called (and the direct reference to
     * the per-tls_CTX settings would be lost, but those still were
     * indirectly accessed for various purposes, and for that reason they
     * used to be known as s->ctx->default_cert). Now we don't look at the
     * tls_CTX's CERT after having duplicated it once.
     */
    s->cert = tls_cert_dup(ctx->cert);
    if (s->cert == NULL)
        goto err;

    RECORD_LAYER_set_read_ahead(&s->rlayer, ctx->read_ahead);
    s->msg_callback = ctx->msg_callback;
    s->msg_callback_arg = ctx->msg_callback_arg;
    s->verify_mode = ctx->verify_mode;
    s->not_resumable_session_cb = ctx->not_resumable_session_cb;
    s->record_padding_cb = ctx->record_padding_cb;
    s->record_padding_arg = ctx->record_padding_arg;
    s->block_padding = ctx->block_padding;
    s->sid_ctx_length = ctx->sid_ctx_length;
    if (!otls_assert(s->sid_ctx_length <= sizeof(s->sid_ctx)))
        goto err;
    memcpy(&s->sid_ctx, &ctx->sid_ctx, sizeof(s->sid_ctx));
    s->verify_callback = ctx->default_verify_callback;
    s->generate_session_id = ctx->generate_session_id;

    s->param = X509_VERIFY_PARAM_new();
    if (s->param == NULL)
        goto err;
    X509_VERIFY_PARAM_inherit(s->param, ctx->param);
    s->quiet_shutdown = ctx->quiet_shutdown;

    s->ext.max_fragment_len_mode = ctx->ext.max_fragment_len_mode;
    s->max_send_fragment = ctx->max_send_fragment;
    s->split_send_fragment = ctx->split_send_fragment;
    s->max_pipelines = ctx->max_pipelines;
    if (s->max_pipelines > 1)
        RECORD_LAYER_set_read_ahead(&s->rlayer, 1);
    if (ctx->default_read_buf_len > 0)
        tls_set_default_read_buffer_len(s, ctx->default_read_buf_len);

    tls_CTX_up_ref(ctx);
    s->ctx = ctx;
    s->ext.debug_cb = 0;
    s->ext.debug_arg = NULL;
    s->ext.ticket_expected = 0;
    s->ext.status_type = ctx->ext.status_type;
    s->ext.status_expected = 0;
    s->ext.ocsp.ids = NULL;
    s->ext.ocsp.exts = NULL;
    s->ext.ocsp.resp = NULL;
    s->ext.ocsp.resp_len = 0;
    tls_CTX_up_ref(ctx);
    s->session_ctx = ctx;
#ifndef OPENtls_NO_EC
    if (ctx->ext.ecpointformats) {
        s->ext.ecpointformats =
            OPENtls_memdup(ctx->ext.ecpointformats,
                           ctx->ext.ecpointformats_len);
        if (!s->ext.ecpointformats)
            goto err;
        s->ext.ecpointformats_len =
            ctx->ext.ecpointformats_len;
    }
#endif
    if (ctx->ext.supportedgroups) {
        s->ext.supportedgroups =
            OPENtls_memdup(ctx->ext.supportedgroups,
                           ctx->ext.supportedgroups_len
                                * sizeof(*ctx->ext.supportedgroups));
        if (!s->ext.supportedgroups)
            goto err;
        s->ext.supportedgroups_len = ctx->ext.supportedgroups_len;
    }

#ifndef OPENtls_NO_NEXTPROTONEG
    s->ext.npn = NULL;
#endif

    if (s->ctx->ext.alpn) {
        s->ext.alpn = OPENtls_malloc(s->ctx->ext.alpn_len);
        if (s->ext.alpn == NULL)
            goto err;
        memcpy(s->ext.alpn, s->ctx->ext.alpn, s->ctx->ext.alpn_len);
        s->ext.alpn_len = s->ctx->ext.alpn_len;
    }

    s->verified_chain = NULL;
    s->verify_result = X509_V_OK;

    s->default_passwd_callback = ctx->default_passwd_callback;
    s->default_passwd_callback_userdata = ctx->default_passwd_callback_userdata;

    s->method = ctx->method;

    s->key_update = tls_KEY_UPDATE_NONE;

    s->allow_early_data_cb = ctx->allow_early_data_cb;
    s->allow_early_data_cb_data = ctx->allow_early_data_cb_data;

    if (!s->method->tls_new(s))
        goto err;

    s->server = (ctx->method->tls_accept == tls_undefined_function) ? 0 : 1;

    if (!tls_clear(s))
        goto err;

    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_tls, s, &s->ex_data))
        goto err;

#ifndef OPENtls_NO_PSK
    s->psk_client_callback = ctx->psk_client_callback;
    s->psk_server_callback = ctx->psk_server_callback;
#endif
    s->psk_find_session_cb = ctx->psk_find_session_cb;
    s->psk_use_session_cb = ctx->psk_use_session_cb;

    s->async_cb = ctx->async_cb;
    s->async_cb_arg = ctx->async_cb_arg;

    s->job = NULL;

#ifndef OPENtls_NO_CT
    if (!tls_set_ct_validation_callback(s, ctx->ct_validation_callback,
                                        ctx->ct_validation_callback_arg))
        goto err;
#endif

    return s;
 err:
    tls_free(s);
    tlserr(tls_F_tls_NEW, ERR_R_MALLOC_FAILURE);
    return NULL;
}

int tls_is_dtls(const tls *s)
{
    return tls_IS_DTLS(s) ? 1 : 0;
}

int tls_up_ref(tls *s)
{
    int i;

    if (CRYPTO_UP_REF(&s->references, &i, s->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("tls", s);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

int tls_CTX_set_session_id_context(tls_CTX *ctx, const unsigned char *sid_ctx,
                                   unsigned int sid_ctx_len)
{
    if (sid_ctx_len > tls_MAX_SID_CTX_LENGTH) {
        tlserr(tls_F_tls_CTX_SET_SESSION_ID_CONTEXT,
               tls_R_tls_SESSION_ID_CONTEXT_TOO_LONG);
        return 0;
    }
    ctx->sid_ctx_length = sid_ctx_len;
    memcpy(ctx->sid_ctx, sid_ctx, sid_ctx_len);

    return 1;
}

int tls_set_session_id_context(tls *tls, const unsigned char *sid_ctx,
                               unsigned int sid_ctx_len)
{
    if (sid_ctx_len > tls_MAX_SID_CTX_LENGTH) {
        tlserr(tls_F_tls_SET_SESSION_ID_CONTEXT,
               tls_R_tls_SESSION_ID_CONTEXT_TOO_LONG);
        return 0;
    }
    tls->sid_ctx_length = sid_ctx_len;
    memcpy(tls->sid_ctx, sid_ctx, sid_ctx_len);

    return 1;
}

int tls_CTX_set_generate_session_id(tls_CTX *ctx, GEN_SESSION_CB cb)
{
    CRYPTO_THREAD_write_lock(ctx->lock);
    ctx->generate_session_id = cb;
    CRYPTO_THREAD_unlock(ctx->lock);
    return 1;
}

int tls_set_generate_session_id(tls *tls, GEN_SESSION_CB cb)
{
    CRYPTO_THREAD_write_lock(tls->lock);
    tls->generate_session_id = cb;
    CRYPTO_THREAD_unlock(tls->lock);
    return 1;
}

int tls_has_matching_session_id(const tls *tls, const unsigned char *id,
                                unsigned int id_len)
{
    /*
     * A quick examination of tls_SESSION_hash and tls_SESSION_cmp shows how
     * we can "construct" a session to give us the desired check - i.e. to
     * find if there's a session in the hash table that would conflict with
     * any new session built out of this id/id_len and the tls_version in use
     * by this tls.
     */
    tls_SESSION r, *p;

    if (id_len > sizeof(r.session_id))
        return 0;

    r.tls_version = tls->version;
    r.session_id_length = id_len;
    memcpy(r.session_id, id, id_len);

    CRYPTO_THREAD_read_lock(tls->session_ctx->lock);
    p = lh_tls_SESSION_retrieve(tls->session_ctx->sessions, &r);
    CRYPTO_THREAD_unlock(tls->session_ctx->lock);
    return (p != NULL);
}

int tls_CTX_set_purpose(tls_CTX *s, int purpose)
{
    return X509_VERIFY_PARAM_set_purpose(s->param, purpose);
}

int tls_set_purpose(tls *s, int purpose)
{
    return X509_VERIFY_PARAM_set_purpose(s->param, purpose);
}

int tls_CTX_set_trust(tls_CTX *s, int trust)
{
    return X509_VERIFY_PARAM_set_trust(s->param, trust);
}

int tls_set_trust(tls *s, int trust)
{
    return X509_VERIFY_PARAM_set_trust(s->param, trust);
}

int tls_set1_host(tls *s, const char *hostname)
{
    return X509_VERIFY_PARAM_set1_host(s->param, hostname, 0);
}

int tls_add1_host(tls *s, const char *hostname)
{
    return X509_VERIFY_PARAM_add1_host(s->param, hostname, 0);
}

void tls_set_hostflags(tls *s, unsigned int flags)
{
    X509_VERIFY_PARAM_set_hostflags(s->param, flags);
}

const char *tls_get0_peername(tls *s)
{
    return X509_VERIFY_PARAM_get0_peername(s->param);
}

int tls_CTX_dane_enable(tls_CTX *ctx)
{
    return dane_ctx_enable(&ctx->dane);
}

unsigned long tls_CTX_dane_set_flags(tls_CTX *ctx, unsigned long flags)
{
    unsigned long orig = ctx->dane.flags;

    ctx->dane.flags |= flags;
    return orig;
}

unsigned long tls_CTX_dane_clear_flags(tls_CTX *ctx, unsigned long flags)
{
    unsigned long orig = ctx->dane.flags;

    ctx->dane.flags &= ~flags;
    return orig;
}

int tls_dane_enable(tls *s, const char *basedomain)
{
    tls_DANE *dane = &s->dane;

    if (s->ctx->dane.mdmax == 0) {
        tlserr(tls_F_tls_DANE_ENABLE, tls_R_CONTEXT_NOT_DANE_ENABLED);
        return 0;
    }
    if (dane->trecs != NULL) {
        tlserr(tls_F_tls_DANE_ENABLE, tls_R_DANE_ALREADY_ENABLED);
        return 0;
    }

    /*
     * Default SNI name.  This rejects empty names, while set1_host below
     * accepts them and disables host name checks.  To avoid side-effects with
     * invalid input, set the SNI name first.
     */
    if (s->ext.hostname == NULL) {
        if (!tls_set_tlsext_host_name(s, basedomain)) {
            tlserr(tls_F_tls_DANE_ENABLE, tls_R_ERROR_SETTING_TLSA_BASE_DOMAIN);
            return -1;
        }
    }

    /* Primary RFC6125 reference identifier */
    if (!X509_VERIFY_PARAM_set1_host(s->param, basedomain, 0)) {
        tlserr(tls_F_tls_DANE_ENABLE, tls_R_ERROR_SETTING_TLSA_BASE_DOMAIN);
        return -1;
    }

    dane->mdpth = -1;
    dane->pdpth = -1;
    dane->dctx = &s->ctx->dane;
    dane->trecs = sk_danetls_record_new_null();

    if (dane->trecs == NULL) {
        tlserr(tls_F_tls_DANE_ENABLE, ERR_R_MALLOC_FAILURE);
        return -1;
    }
    return 1;
}

unsigned long tls_dane_set_flags(tls *tls, unsigned long flags)
{
    unsigned long orig = tls->dane.flags;

    tls->dane.flags |= flags;
    return orig;
}

unsigned long tls_dane_clear_flags(tls *tls, unsigned long flags)
{
    unsigned long orig = tls->dane.flags;

    tls->dane.flags &= ~flags;
    return orig;
}

int tls_get0_dane_authority(tls *s, X509 **mcert, EVP_PKEY **mspki)
{
    tls_DANE *dane = &s->dane;

    if (!DANETLS_ENABLED(dane) || s->verify_result != X509_V_OK)
        return -1;
    if (dane->mtlsa) {
        if (mcert)
            *mcert = dane->mcert;
        if (mspki)
            *mspki = (dane->mcert == NULL) ? dane->mtlsa->spki : NULL;
    }
    return dane->mdpth;
}

int tls_get0_dane_tlsa(tls *s, uint8_t *usage, uint8_t *selector,
                       uint8_t *mtype, unsigned const char **data, size_t *dlen)
{
    tls_DANE *dane = &s->dane;

    if (!DANETLS_ENABLED(dane) || s->verify_result != X509_V_OK)
        return -1;
    if (dane->mtlsa) {
        if (usage)
            *usage = dane->mtlsa->usage;
        if (selector)
            *selector = dane->mtlsa->selector;
        if (mtype)
            *mtype = dane->mtlsa->mtype;
        if (data)
            *data = dane->mtlsa->data;
        if (dlen)
            *dlen = dane->mtlsa->dlen;
    }
    return dane->mdpth;
}

tls_DANE *tls_get0_dane(tls *s)
{
    return &s->dane;
}

int tls_dane_tlsa_add(tls *s, uint8_t usage, uint8_t selector,
                      uint8_t mtype, unsigned const char *data, size_t dlen)
{
    return dane_tlsa_add(&s->dane, usage, selector, mtype, data, dlen);
}

int tls_CTX_dane_mtype_set(tls_CTX *ctx, const EVP_MD *md, uint8_t mtype,
                           uint8_t ord)
{
    return dane_mtype_set(&ctx->dane, md, mtype, ord);
}

int tls_CTX_set1_param(tls_CTX *ctx, X509_VERIFY_PARAM *vpm)
{
    return X509_VERIFY_PARAM_set1(ctx->param, vpm);
}

int tls_set1_param(tls *tls, X509_VERIFY_PARAM *vpm)
{
    return X509_VERIFY_PARAM_set1(tls->param, vpm);
}

X509_VERIFY_PARAM *tls_CTX_get0_param(tls_CTX *ctx)
{
    return ctx->param;
}

X509_VERIFY_PARAM *tls_get0_param(tls *tls)
{
    return tls->param;
}

void tls_certs_clear(tls *s)
{
    tls_cert_clear_certs(s->cert);
}

void tls_free(tls *s)
{
    int i;

    if (s == NULL)
        return;
    CRYPTO_DOWN_REF(&s->references, &i, s->lock);
    REF_PRINT_COUNT("tls", s);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    X509_VERIFY_PARAM_free(s->param);
    dane_final(&s->dane);
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_tls, s, &s->ex_data);

    RECORD_LAYER_release(&s->rlayer);

    /* Ignore return value */
    tls_free_wbio_buffer(s);

    BIO_free_all(s->wbio);
    s->wbio = NULL;
    BIO_free_all(s->rbio);
    s->rbio = NULL;

    BUF_MEM_free(s->init_buf);

    /* add extra stuff */
    sk_tls_CIPHER_free(s->cipher_list);
    sk_tls_CIPHER_free(s->cipher_list_by_id);
    sk_tls_CIPHER_free(s->tls13_ciphersuites);
    sk_tls_CIPHER_free(s->peer_ciphers);

    /* Make the next call work :-) */
    if (s->session != NULL) {
        tls_clear_bad_session(s);
        tls_SESSION_free(s->session);
    }
    tls_SESSION_free(s->psksession);
    OPENtls_free(s->psksession_id);

    clear_ciphers(s);

    tls_cert_free(s->cert);
    OPENtls_free(s->shared_sigalgs);
    /* Free up if allocated */

    OPENtls_free(s->ext.hostname);
    tls_CTX_free(s->session_ctx);
#ifndef OPENtls_NO_EC
    OPENtls_free(s->ext.ecpointformats);
    OPENtls_free(s->ext.peer_ecpointformats);
#endif                          /* OPENtls_NO_EC */
    OPENtls_free(s->ext.supportedgroups);
    OPENtls_free(s->ext.peer_supportedgroups);
    sk_X509_EXTENSION_pop_free(s->ext.ocsp.exts, X509_EXTENSION_free);
#ifndef OPENtls_NO_OCSP
    sk_OCSP_RESPID_pop_free(s->ext.ocsp.ids, OCSP_RESPID_free);
#endif
#ifndef OPENtls_NO_CT
    SCT_LIST_free(s->scts);
    OPENtls_free(s->ext.scts);
#endif
    OPENtls_free(s->ext.ocsp.resp);
    OPENtls_free(s->ext.alpn);
    OPENtls_free(s->ext.tls13_cookie);
    OPENtls_free(s->clienthello);
    OPENtls_free(s->pha_context);
    EVP_MD_CTX_free(s->pha_dgst);

    sk_X509_NAME_pop_free(s->ca_names, X509_NAME_free);
    sk_X509_NAME_pop_free(s->client_ca_names, X509_NAME_free);

    sk_X509_pop_free(s->verified_chain, X509_free);

    if (s->method != NULL)
        s->method->tls_free(s);

    tls_CTX_free(s->ctx);

    ASYNC_WAIT_CTX_free(s->waitctx);

#if !defined(OPENtls_NO_NEXTPROTONEG)
    OPENtls_free(s->ext.npn);
#endif

#ifndef OPENtls_NO_SRTP
    sk_SRTP_PROTECTION_PROFILE_free(s->srtp_profiles);
#endif

    CRYPTO_THREAD_lock_free(s->lock);

    OPENtls_free(s);
}

void tls_set0_rbio(tls *s, BIO *rbio)
{
    BIO_free_all(s->rbio);
    s->rbio = rbio;
}

void tls_set0_wbio(tls *s, BIO *wbio)
{
    /*
     * If the output buffering BIO is still in place, remove it
     */
    if (s->bbio != NULL)
        s->wbio = BIO_pop(s->wbio);

    BIO_free_all(s->wbio);
    s->wbio = wbio;

    /* Re-attach |bbio| to the new |wbio|. */
    if (s->bbio != NULL)
        s->wbio = BIO_push(s->bbio, s->wbio);
}

void tls_set_bio(tls *s, BIO *rbio, BIO *wbio)
{
    /*
     * For historical reasons, this function has many different cases in
     * ownership handling.
     */

    /* If nothing has changed, do nothing */
    if (rbio == tls_get_rbio(s) && wbio == tls_get_wbio(s))
        return;

    /*
     * If the two arguments are equal then one fewer reference is granted by the
     * caller than we want to take
     */
    if (rbio != NULL && rbio == wbio)
        BIO_up_ref(rbio);

    /*
     * If only the wbio is changed only adopt one reference.
     */
    if (rbio == tls_get_rbio(s)) {
        tls_set0_wbio(s, wbio);
        return;
    }
    /*
     * There is an asymmetry here for historical reasons. If only the rbio is
     * changed AND the rbio and wbio were originally different, then we only
     * adopt one reference.
     */
    if (wbio == tls_get_wbio(s) && tls_get_rbio(s) != tls_get_wbio(s)) {
        tls_set0_rbio(s, rbio);
        return;
    }

    /* Otherwise, adopt both references. */
    tls_set0_rbio(s, rbio);
    tls_set0_wbio(s, wbio);
}

BIO *tls_get_rbio(const tls *s)
{
    return s->rbio;
}

BIO *tls_get_wbio(const tls *s)
{
    if (s->bbio != NULL) {
        /*
         * If |bbio| is active, the true caller-configured BIO is its
         * |next_bio|.
         */
        return BIO_next(s->bbio);
    }
    return s->wbio;
}

int tls_get_fd(const tls *s)
{
    return tls_get_rfd(s);
}

int tls_get_rfd(const tls *s)
{
    int ret = -1;
    BIO *b, *r;

    b = tls_get_rbio(s);
    r = BIO_find_type(b, BIO_TYPE_DESCRIPTOR);
    if (r != NULL)
        BIO_get_fd(r, &ret);
    return ret;
}

int tls_get_wfd(const tls *s)
{
    int ret = -1;
    BIO *b, *r;

    b = tls_get_wbio(s);
    r = BIO_find_type(b, BIO_TYPE_DESCRIPTOR);
    if (r != NULL)
        BIO_get_fd(r, &ret);
    return ret;
}

#ifndef OPENtls_NO_SOCK
int tls_set_fd(tls *s, int fd)
{
    int ret = 0;
    BIO *bio = NULL;

    bio = BIO_new(BIO_s_socket());

    if (bio == NULL) {
        tlserr(tls_F_tls_SET_FD, ERR_R_BUF_LIB);
        goto err;
    }
    BIO_set_fd(bio, fd, BIO_NOCLOSE);
    tls_set_bio(s, bio, bio);
#ifndef OPENtls_NO_KTLS
    /*
     * The new socket is created successfully regardless of ktls_enable.
     * ktls_enable doesn't change any functionality of the socket, except
     * changing the setsockopt to enable the processing of ktls_start.
     * Thus, it is not a problem to call it for non-TLS sockets.
     */
    ktls_enable(fd);
#endif /* OPENtls_NO_KTLS */
    ret = 1;
 err:
    return ret;
}

int tls_set_wfd(tls *s, int fd)
{
    BIO *rbio = tls_get_rbio(s);

    if (rbio == NULL || BIO_method_type(rbio) != BIO_TYPE_SOCKET
        || (int)BIO_get_fd(rbio, NULL) != fd) {
        BIO *bio = BIO_new(BIO_s_socket());

        if (bio == NULL) {
            tlserr(tls_F_tls_SET_WFD, ERR_R_BUF_LIB);
            return 0;
        }
        BIO_set_fd(bio, fd, BIO_NOCLOSE);
        tls_set0_wbio(s, bio);
#ifndef OPENtls_NO_KTLS
        /*
         * The new socket is created successfully regardless of ktls_enable.
         * ktls_enable doesn't change any functionality of the socket, except
         * changing the setsockopt to enable the processing of ktls_start.
         * Thus, it is not a problem to call it for non-TLS sockets.
         */
        ktls_enable(fd);
#endif /* OPENtls_NO_KTLS */
    } else {
        BIO_up_ref(rbio);
        tls_set0_wbio(s, rbio);
    }
    return 1;
}

int tls_set_rfd(tls *s, int fd)
{
    BIO *wbio = tls_get_wbio(s);

    if (wbio == NULL || BIO_method_type(wbio) != BIO_TYPE_SOCKET
        || ((int)BIO_get_fd(wbio, NULL) != fd)) {
        BIO *bio = BIO_new(BIO_s_socket());

        if (bio == NULL) {
            tlserr(tls_F_tls_SET_RFD, ERR_R_BUF_LIB);
            return 0;
        }
        BIO_set_fd(bio, fd, BIO_NOCLOSE);
        tls_set0_rbio(s, bio);
    } else {
        BIO_up_ref(wbio);
        tls_set0_rbio(s, wbio);
    }

    return 1;
}
#endif

/* return length of latest Finished message we sent, copy to 'buf' */
size_t tls_get_finished(const tls *s, void *buf, size_t count)
{
    size_t ret = 0;

    ret = s->s3.tmp.finish_md_len;
    if (count > ret)
        count = ret;
    memcpy(buf, s->s3.tmp.finish_md, count);
    return ret;
}

/* return length of latest Finished message we expected, copy to 'buf' */
size_t tls_get_peer_finished(const tls *s, void *buf, size_t count)
{
    size_t ret = 0;

    ret = s->s3.tmp.peer_finish_md_len;
    if (count > ret)
        count = ret;
    memcpy(buf, s->s3.tmp.peer_finish_md, count);
    return ret;
}

int tls_get_verify_mode(const tls *s)
{
    return s->verify_mode;
}

int tls_get_verify_depth(const tls *s)
{
    return X509_VERIFY_PARAM_get_depth(s->param);
}

int (*tls_get_verify_callback(const tls *s)) (int, X509_STORE_CTX *) {
    return s->verify_callback;
}

int tls_CTX_get_verify_mode(const tls_CTX *ctx)
{
    return ctx->verify_mode;
}

int tls_CTX_get_verify_depth(const tls_CTX *ctx)
{
    return X509_VERIFY_PARAM_get_depth(ctx->param);
}

int (*tls_CTX_get_verify_callback(const tls_CTX *ctx)) (int, X509_STORE_CTX *) {
    return ctx->default_verify_callback;
}

void tls_set_verify(tls *s, int mode,
                    int (*callback) (int ok, X509_STORE_CTX *ctx))
{
    s->verify_mode = mode;
    if (callback != NULL)
        s->verify_callback = callback;
}

void tls_set_verify_depth(tls *s, int depth)
{
    X509_VERIFY_PARAM_set_depth(s->param, depth);
}

void tls_set_read_ahead(tls *s, int yes)
{
    RECORD_LAYER_set_read_ahead(&s->rlayer, yes);
}

int tls_get_read_ahead(const tls *s)
{
    return RECORD_LAYER_get_read_ahead(&s->rlayer);
}

int tls_pending(const tls *s)
{
    size_t pending = s->method->tls_pending(s);

    /*
     * tls_pending cannot work properly if read-ahead is enabled
     * (tls_[CTX_]ctrl(..., tls_CTRL_SET_READ_AHEAD, 1, NULL)), and it is
     * impossible to fix since tls_pending cannot report errors that may be
     * observed while scanning the new data. (Note that tls_pending() is
     * often used as a boolean value, so we'd better not return -1.)
     *
     * tls_pending also cannot work properly if the value >INT_MAX. In that case
     * we just return INT_MAX.
     */
    return pending < INT_MAX ? (int)pending : INT_MAX;
}

int tls_has_pending(const tls *s)
{
    /*
     * Similar to tls_pending() but returns a 1 to indicate that we have
     * unprocessed data available or 0 otherwise (as opposed to the number of
     * bytes available). Unlike tls_pending() this will take into account
     * read_ahead data. A 1 return simply indicates that we have unprocessed
     * data. That data may not result in any application data, or we may fail
     * to parse the records for some reason.
     */
    if (RECORD_LAYER_processed_read_pending(&s->rlayer))
        return 1;

    return RECORD_LAYER_read_pending(&s->rlayer);
}

X509 *tls_get_peer_certificate(const tls *s)
{
    X509 *r;

    if ((s == NULL) || (s->session == NULL))
        r = NULL;
    else
        r = s->session->peer;

    if (r == NULL)
        return r;

    X509_up_ref(r);

    return r;
}

STACK_OF(X509) *tls_get_peer_cert_chain(const tls *s)
{
    STACK_OF(X509) *r;

    if ((s == NULL) || (s->session == NULL))
        r = NULL;
    else
        r = s->session->peer_chain;

    /*
     * If we are a client, cert_chain includes the peer's own certificate; if
     * we are a server, it does not.
     */

    return r;
}

/*
 * Now in theory, since the calling process own 't' it should be safe to
 * modify.  We need to be able to read f without being hatlsed
 */
int tls_copy_session_id(tls *t, const tls *f)
{
    int i;
    /* Do we need to to tls locking? */
    if (!tls_set_session(t, tls_get_session(f))) {
        return 0;
    }

    /*
     * what if we are setup for one protocol version but want to talk another
     */
    if (t->method != f->method) {
        t->method->tls_free(t);
        t->method = f->method;
        if (t->method->tls_new(t) == 0)
            return 0;
    }

    CRYPTO_UP_REF(&f->cert->references, &i, f->cert->lock);
    tls_cert_free(t->cert);
    t->cert = f->cert;
    if (!tls_set_session_id_context(t, f->sid_ctx, (int)f->sid_ctx_length)) {
        return 0;
    }

    return 1;
}

/* Fix this so it checks all the valid key/cert options */
int tls_CTX_check_private_key(const tls_CTX *ctx)
{
    if ((ctx == NULL) || (ctx->cert->key->x509 == NULL)) {
        tlserr(tls_F_tls_CTX_CHECK_PRIVATE_KEY, tls_R_NO_CERTIFICATE_ASSIGNED);
        return 0;
    }
    if (ctx->cert->key->privatekey == NULL) {
        tlserr(tls_F_tls_CTX_CHECK_PRIVATE_KEY, tls_R_NO_PRIVATE_KEY_ASSIGNED);
        return 0;
    }
    return X509_check_private_key
            (ctx->cert->key->x509, ctx->cert->key->privatekey);
}

/* Fix this function so that it takes an optional type parameter */
int tls_check_private_key(const tls *tls)
{
    if (tls == NULL) {
        tlserr(tls_F_tls_CHECK_PRIVATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (tls->cert->key->x509 == NULL) {
        tlserr(tls_F_tls_CHECK_PRIVATE_KEY, tls_R_NO_CERTIFICATE_ASSIGNED);
        return 0;
    }
    if (tls->cert->key->privatekey == NULL) {
        tlserr(tls_F_tls_CHECK_PRIVATE_KEY, tls_R_NO_PRIVATE_KEY_ASSIGNED);
        return 0;
    }
    return X509_check_private_key(tls->cert->key->x509,
                                   tls->cert->key->privatekey);
}

int tls_waiting_for_async(tls *s)
{
    if (s->job)
        return 1;

    return 0;
}

int tls_get_all_async_fds(tls *s, Otls_ASYNC_FD *fds, size_t *numfds)
{
    ASYNC_WAIT_CTX *ctx = s->waitctx;

    if (ctx == NULL)
        return 0;
    return ASYNC_WAIT_CTX_get_all_fds(ctx, fds, numfds);
}

int tls_get_changed_async_fds(tls *s, Otls_ASYNC_FD *addfd, size_t *numaddfds,
                              Otls_ASYNC_FD *delfd, size_t *numdelfds)
{
    ASYNC_WAIT_CTX *ctx = s->waitctx;

    if (ctx == NULL)
        return 0;
    return ASYNC_WAIT_CTX_get_changed_fds(ctx, addfd, numaddfds, delfd,
                                          numdelfds);
}

int tls_CTX_set_async_callback(tls_CTX *ctx, tls_async_callback_fn callback)
{
    ctx->async_cb = callback;
    return 1;
}

int tls_CTX_set_async_callback_arg(tls_CTX *ctx, void *arg)
{
    ctx->async_cb_arg = arg;
    return 1;
}

int tls_set_async_callback(tls *s, tls_async_callback_fn callback)
{
    s->async_cb = callback;
    return 1;
}

int tls_set_async_callback_arg(tls *s, void *arg)
{
    s->async_cb_arg = arg;
    return 1;
}

int tls_get_async_status(tls *s, int *status)
{
    ASYNC_WAIT_CTX *ctx = s->waitctx;

    if (ctx == NULL)
        return 0;
    *status = ASYNC_WAIT_CTX_get_status(ctx);
    return 1;
}

int tls_accept(tls *s)
{
    if (s->handshake_func == NULL) {
        /* Not properly initialized yet */
        tls_set_accept_state(s);
    }

    return tls_do_handshake(s);
}

int tls_connect(tls *s)
{
    if (s->handshake_func == NULL) {
        /* Not properly initialized yet */
        tls_set_connect_state(s);
    }

    return tls_do_handshake(s);
}

long tls_get_default_timeout(const tls *s)
{
    return s->method->get_timeout();
}

static int tls_async_wait_ctx_cb(void *arg)
{
    tls *s = (tls *)arg;

    return s->async_cb(s, s->async_cb_arg);
}

static int tls_start_async_job(tls *s, struct tls_async_args *args,
                               int (*func) (void *))
{
    int ret;
    if (s->waitctx == NULL) {
        s->waitctx = ASYNC_WAIT_CTX_new();
        if (s->waitctx == NULL)
            return -1;
        if (s->async_cb != NULL
            && !ASYNC_WAIT_CTX_set_callback
                 (s->waitctx, tls_async_wait_ctx_cb, s))
            return -1;
    }
    switch (ASYNC_start_job(&s->job, s->waitctx, &ret, func, args,
                            sizeof(struct tls_async_args))) {
    case ASYNC_ERR:
        s->rwstate = tls_NOTHING;
        tlserr(tls_F_tls_START_ASYNC_JOB, tls_R_FAILED_TO_INIT_ASYNC);
        return -1;
    case ASYNC_PAUSE:
        s->rwstate = tls_ASYNC_PAUSED;
        return -1;
    case ASYNC_NO_JOBS:
        s->rwstate = tls_ASYNC_NO_JOBS;
        return -1;
    case ASYNC_FINISH:
        s->job = NULL;
        return ret;
    default:
        s->rwstate = tls_NOTHING;
        tlserr(tls_F_tls_START_ASYNC_JOB, ERR_R_INTERNAL_ERROR);
        /* Shouldn't happen */
        return -1;
    }
}

static int tls_io_intern(void *vargs)
{
    struct tls_async_args *args;
    tls *s;
    void *buf;
    size_t num;

    args = (struct tls_async_args *)vargs;
    s = args->s;
    buf = args->buf;
    num = args->num;
    switch (args->type) {
    case READFUNC:
        return args->f.func_read(s, buf, num, &s->asyncrw);
    case WRITEFUNC:
        return args->f.func_write(s, buf, num, &s->asyncrw);
    case OTHERFUNC:
        return args->f.func_other(s);
    }
    return -1;
}

int tls_read_internal(tls *s, void *buf, size_t num, size_t *readbytes)
{
    if (s->handshake_func == NULL) {
        tlserr(tls_F_tls_READ_INTERNAL, tls_R_UNINITIALIZED);
        return -1;
    }

    if (s->shutdown & tls_RECEIVED_SHUTDOWN) {
        s->rwstate = tls_NOTHING;
        return 0;
    }

    if (s->early_data_state == tls_EARLY_DATA_CONNECT_RETRY
                || s->early_data_state == tls_EARLY_DATA_ACCEPT_RETRY) {
        tlserr(tls_F_tls_READ_INTERNAL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    /*
     * If we are a client and haven't received the ServerHello etc then we
     * better do that
     */
    otls_statem_check_finish_init(s, 0);

    if ((s->mode & tls_MODE_ASYNC) && ASYNC_get_current_job() == NULL) {
        struct tls_async_args args;
        int ret;

        args.s = s;
        args.buf = buf;
        args.num = num;
        args.type = READFUNC;
        args.f.func_read = s->method->tls_read;

        ret = tls_start_async_job(s, &args, tls_io_intern);
        *readbytes = s->asyncrw;
        return ret;
    } else {
        return s->method->tls_read(s, buf, num, readbytes);
    }
}

int tls_read(tls *s, void *buf, int num)
{
    int ret;
    size_t readbytes;

    if (num < 0) {
        tlserr(tls_F_tls_READ, tls_R_BAD_LENGTH);
        return -1;
    }

    ret = tls_read_internal(s, buf, (size_t)num, &readbytes);

    /*
     * The cast is safe here because ret should be <= INT_MAX because num is
     * <= INT_MAX
     */
    if (ret > 0)
        ret = (int)readbytes;

    return ret;
}

int tls_read_ex(tls *s, void *buf, size_t num, size_t *readbytes)
{
    int ret = tls_read_internal(s, buf, num, readbytes);

    if (ret < 0)
        ret = 0;
    return ret;
}

int tls_read_early_data(tls *s, void *buf, size_t num, size_t *readbytes)
{
    int ret;

    if (!s->server) {
        tlserr(tls_F_tls_READ_EARLY_DATA, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return tls_READ_EARLY_DATA_ERROR;
    }

    switch (s->early_data_state) {
    case tls_EARLY_DATA_NONE:
        if (!tls_in_before(s)) {
            tlserr(tls_F_tls_READ_EARLY_DATA,
                   ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            return tls_READ_EARLY_DATA_ERROR;
        }
        /* fall through */

    case tls_EARLY_DATA_ACCEPT_RETRY:
        s->early_data_state = tls_EARLY_DATA_ACCEPTING;
        ret = tls_accept(s);
        if (ret <= 0) {
            /* NBIO or error */
            s->early_data_state = tls_EARLY_DATA_ACCEPT_RETRY;
            return tls_READ_EARLY_DATA_ERROR;
        }
        /* fall through */

    case tls_EARLY_DATA_READ_RETRY:
        if (s->ext.early_data == tls_EARLY_DATA_ACCEPTED) {
            s->early_data_state = tls_EARLY_DATA_READING;
            ret = tls_read_ex(s, buf, num, readbytes);
            /*
             * State machine will update early_data_state to
             * tls_EARLY_DATA_FINISHED_READING if we get an EndOfEarlyData
             * message
             */
            if (ret > 0 || (ret <= 0 && s->early_data_state
                                        != tls_EARLY_DATA_FINISHED_READING)) {
                s->early_data_state = tls_EARLY_DATA_READ_RETRY;
                return ret > 0 ? tls_READ_EARLY_DATA_SUCCESS
                               : tls_READ_EARLY_DATA_ERROR;
            }
        } else {
            s->early_data_state = tls_EARLY_DATA_FINISHED_READING;
        }
        *readbytes = 0;
        return tls_READ_EARLY_DATA_FINISH;

    default:
        tlserr(tls_F_tls_READ_EARLY_DATA, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return tls_READ_EARLY_DATA_ERROR;
    }
}

int tls_get_early_data_status(const tls *s)
{
    return s->ext.early_data;
}

static int tls_peek_internal(tls *s, void *buf, size_t num, size_t *readbytes)
{
    if (s->handshake_func == NULL) {
        tlserr(tls_F_tls_PEEK_INTERNAL, tls_R_UNINITIALIZED);
        return -1;
    }

    if (s->shutdown & tls_RECEIVED_SHUTDOWN) {
        return 0;
    }
    if ((s->mode & tls_MODE_ASYNC) && ASYNC_get_current_job() == NULL) {
        struct tls_async_args args;
        int ret;

        args.s = s;
        args.buf = buf;
        args.num = num;
        args.type = READFUNC;
        args.f.func_read = s->method->tls_peek;

        ret = tls_start_async_job(s, &args, tls_io_intern);
        *readbytes = s->asyncrw;
        return ret;
    } else {
        return s->method->tls_peek(s, buf, num, readbytes);
    }
}

int tls_peek(tls *s, void *buf, int num)
{
    int ret;
    size_t readbytes;

    if (num < 0) {
        tlserr(tls_F_tls_PEEK, tls_R_BAD_LENGTH);
        return -1;
    }

    ret = tls_peek_internal(s, buf, (size_t)num, &readbytes);

    /*
     * The cast is safe here because ret should be <= INT_MAX because num is
     * <= INT_MAX
     */
    if (ret > 0)
        ret = (int)readbytes;

    return ret;
}


int tls_peek_ex(tls *s, void *buf, size_t num, size_t *readbytes)
{
    int ret = tls_peek_internal(s, buf, num, readbytes);

    if (ret < 0)
        ret = 0;
    return ret;
}

int tls_write_internal(tls *s, const void *buf, size_t num, size_t *written)
{
    if (s->handshake_func == NULL) {
        tlserr(tls_F_tls_WRITE_INTERNAL, tls_R_UNINITIALIZED);
        return -1;
    }

    if (s->shutdown & tls_SENT_SHUTDOWN) {
        s->rwstate = tls_NOTHING;
        tlserr(tls_F_tls_WRITE_INTERNAL, tls_R_PROTOCOL_IS_SHUTDOWN);
        return -1;
    }

    if (s->early_data_state == tls_EARLY_DATA_CONNECT_RETRY
                || s->early_data_state == tls_EARLY_DATA_ACCEPT_RETRY
                || s->early_data_state == tls_EARLY_DATA_READ_RETRY) {
        tlserr(tls_F_tls_WRITE_INTERNAL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    /* If we are a client and haven't sent the Finished we better do that */
    otls_statem_check_finish_init(s, 1);

    if ((s->mode & tls_MODE_ASYNC) && ASYNC_get_current_job() == NULL) {
        int ret;
        struct tls_async_args args;

        args.s = s;
        args.buf = (void *)buf;
        args.num = num;
        args.type = WRITEFUNC;
        args.f.func_write = s->method->tls_write;

        ret = tls_start_async_job(s, &args, tls_io_intern);
        *written = s->asyncrw;
        return ret;
    } else {
        return s->method->tls_write(s, buf, num, written);
    }
}

otls_ssize_t tls_sendfile(tls *s, int fd, off_t offset, size_t size, int flags)
{
    otls_ssize_t ret;

    if (s->handshake_func == NULL) {
        tlserr(tls_F_tls_SENDFILE, tls_R_UNINITIALIZED);
        return -1;
    }

    if (s->shutdown & tls_SENT_SHUTDOWN) {
        s->rwstate = tls_NOTHING;
        tlserr(tls_F_tls_SENDFILE, tls_R_PROTOCOL_IS_SHUTDOWN);
        return -1;
    }

    if (!BIO_get_ktls_send(s->wbio)) {
        tlserr(tls_F_tls_SENDFILE, tls_R_UNINITIALIZED);
        return -1;
    }

    /* If we have an alert to send, lets send it */
    if (s->s3.alert_dispatch) {
        ret = (otls_ssize_t)s->method->tls_dispatch_alert(s);
        if (ret <= 0) {
            /* tlsfatal() already called if appropriate */
            return ret;
        }
        /* if it went, fall through and send more stuff */
    }

    s->rwstate = tls_WRITING;
    if (BIO_flush(s->wbio) <= 0) {
        if (!BIO_should_retry(s->wbio)) {
            s->rwstate = tls_NOTHING;
        } else {
#ifdef EAGAIN
            set_sys_error(EAGAIN);
#endif
        }
        return -1;
    }

#ifdef OPENtls_NO_KTLS
    ERR_raise_data(ERR_LIB_SYS, ERR_R_INTERNAL_ERROR, "calling sendfile()");
    return -1;
#else
    ret = ktls_sendfile(tls_get_wfd(s), fd, offset, size, flags);
    if (ret < 0) {
#if defined(EAGAIN) && defined(EINTR) && defined(EBUSY)
        if ((get_last_sys_error() == EAGAIN) ||
            (get_last_sys_error() == EINTR) ||
            (get_last_sys_error() == EBUSY))
            BIO_set_retry_write(s->wbio);
        else
#endif
            tlserr(tls_F_tls_SENDFILE, tls_R_UNINITIALIZED);
        return ret;
    }
    s->rwstate = tls_NOTHING;
    return ret;
#endif
}

int tls_write(tls *s, const void *buf, int num)
{
    int ret;
    size_t written;

    if (num < 0) {
        tlserr(tls_F_tls_WRITE, tls_R_BAD_LENGTH);
        return -1;
    }

    ret = tls_write_internal(s, buf, (size_t)num, &written);

    /*
     * The cast is safe here because ret should be <= INT_MAX because num is
     * <= INT_MAX
     */
    if (ret > 0)
        ret = (int)written;

    return ret;
}

int tls_write_ex(tls *s, const void *buf, size_t num, size_t *written)
{
    int ret = tls_write_internal(s, buf, num, written);

    if (ret < 0)
        ret = 0;
    return ret;
}

int tls_write_early_data(tls *s, const void *buf, size_t num, size_t *written)
{
    int ret, early_data_state;
    size_t writtmp;
    uint32_t partialwrite;

    switch (s->early_data_state) {
    case tls_EARLY_DATA_NONE:
        if (s->server
                || !tls_in_before(s)
                || ((s->session == NULL || s->session->ext.max_early_data == 0)
                     && (s->psk_use_session_cb == NULL))) {
            tlserr(tls_F_tls_WRITE_EARLY_DATA,
                   ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            return 0;
        }
        /* fall through */

    case tls_EARLY_DATA_CONNECT_RETRY:
        s->early_data_state = tls_EARLY_DATA_CONNECTING;
        ret = tls_connect(s);
        if (ret <= 0) {
            /* NBIO or error */
            s->early_data_state = tls_EARLY_DATA_CONNECT_RETRY;
            return 0;
        }
        /* fall through */

    case tls_EARLY_DATA_WRITE_RETRY:
        s->early_data_state = tls_EARLY_DATA_WRITING;
        /*
         * We disable partial write for early data because we don't keep track
         * of how many bytes we've written between the tls_write_ex() call and
         * the flush if the flush needs to be retried)
         */
        partialwrite = s->mode & tls_MODE_ENABLE_PARTIAL_WRITE;
        s->mode &= ~tls_MODE_ENABLE_PARTIAL_WRITE;
        ret = tls_write_ex(s, buf, num, &writtmp);
        s->mode |= partialwrite;
        if (!ret) {
            s->early_data_state = tls_EARLY_DATA_WRITE_RETRY;
            return ret;
        }
        s->early_data_state = tls_EARLY_DATA_WRITE_FLUSH;
        /* fall through */

    case tls_EARLY_DATA_WRITE_FLUSH:
        /* The buffering BIO is still in place so we need to flush it */
        if (statem_flush(s) != 1)
            return 0;
        *written = num;
        s->early_data_state = tls_EARLY_DATA_WRITE_RETRY;
        return 1;

    case tls_EARLY_DATA_FINISHED_READING:
    case tls_EARLY_DATA_READ_RETRY:
        early_data_state = s->early_data_state;
        /* We are a server writing to an unauthenticated client */
        s->early_data_state = tls_EARLY_DATA_UNAUTH_WRITING;
        ret = tls_write_ex(s, buf, num, written);
        /* The buffering BIO is still in place */
        if (ret)
            (void)BIO_flush(s->wbio);
        s->early_data_state = early_data_state;
        return ret;

    default:
        tlserr(tls_F_tls_WRITE_EARLY_DATA, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
}

int tls_shutdown(tls *s)
{
    /*
     * Note that this function behaves differently from what one might
     * expect.  Return values are 0 for no success (yet), 1 for success; but
     * calling it once is usually not enough, even if blocking I/O is used
     * (see tls3_shutdown).
     */

    if (s->handshake_func == NULL) {
        tlserr(tls_F_tls_SHUTDOWN, tls_R_UNINITIALIZED);
        return -1;
    }

    if (!tls_in_init(s)) {
        if ((s->mode & tls_MODE_ASYNC) && ASYNC_get_current_job() == NULL) {
            struct tls_async_args args;

            args.s = s;
            args.type = OTHERFUNC;
            args.f.func_other = s->method->tls_shutdown;

            return tls_start_async_job(s, &args, tls_io_intern);
        } else {
            return s->method->tls_shutdown(s);
        }
    } else {
        tlserr(tls_F_tls_SHUTDOWN, tls_R_SHUTDOWN_WHILE_IN_INIT);
        return -1;
    }
}

int tls_key_update(tls *s, int updatetype)
{
    /*
     * TODO(TLS1.3): How will applications know whether TLSv1.3 has been
     * negotiated, and that it is appropriate to call tls_key_update() instead
     * of tls_renegotiate().
     */
    if (!tls_IS_TLS13(s)) {
        tlserr(tls_F_tls_KEY_UPDATE, tls_R_WRONG_tls_VERSION);
        return 0;
    }

    if (updatetype != tls_KEY_UPDATE_NOT_REQUESTED
            && updatetype != tls_KEY_UPDATE_REQUESTED) {
        tlserr(tls_F_tls_KEY_UPDATE, tls_R_INVALID_KEY_UPDATE_TYPE);
        return 0;
    }

    if (!tls_is_init_finished(s)) {
        tlserr(tls_F_tls_KEY_UPDATE, tls_R_STILL_IN_INIT);
        return 0;
    }

    otls_statem_set_in_init(s, 1);
    s->key_update = updatetype;
    return 1;
}

int tls_get_key_update_type(const tls *s)
{
    return s->key_update;
}

int tls_renegotiate(tls *s)
{
    if (tls_IS_TLS13(s)) {
        tlserr(tls_F_tls_RENEGOTIATE, tls_R_WRONG_tls_VERSION);
        return 0;
    }

    if ((s->options & tls_OP_NO_RENEGOTIATION)) {
        tlserr(tls_F_tls_RENEGOTIATE, tls_R_NO_RENEGOTIATION);
        return 0;
    }

    s->renegotiate = 1;
    s->new_session = 1;

    return s->method->tls_renegotiate(s);
}

int tls_renegotiate_abbreviated(tls *s)
{
    if (tls_IS_TLS13(s)) {
        tlserr(tls_F_tls_RENEGOTIATE_ABBREVIATED, tls_R_WRONG_tls_VERSION);
        return 0;
    }

    if ((s->options & tls_OP_NO_RENEGOTIATION)) {
        tlserr(tls_F_tls_RENEGOTIATE_ABBREVIATED, tls_R_NO_RENEGOTIATION);
        return 0;
    }

    s->renegotiate = 1;
    s->new_session = 0;

    return s->method->tls_renegotiate(s);
}

int tls_renegotiate_pending(const tls *s)
{
    /*
     * becomes true when negotiation is requested; false again once a
     * handshake has finished
     */
    return (s->renegotiate != 0);
}

long tls_ctrl(tls *s, int cmd, long larg, void *parg)
{
    long l;

    switch (cmd) {
    case tls_CTRL_GET_READ_AHEAD:
        return RECORD_LAYER_get_read_ahead(&s->rlayer);
    case tls_CTRL_SET_READ_AHEAD:
        l = RECORD_LAYER_get_read_ahead(&s->rlayer);
        RECORD_LAYER_set_read_ahead(&s->rlayer, larg);
        return l;

    case tls_CTRL_SET_MSG_CALLBACK_ARG:
        s->msg_callback_arg = parg;
        return 1;

    case tls_CTRL_MODE:
        return (s->mode |= larg);
    case tls_CTRL_CLEAR_MODE:
        return (s->mode &= ~larg);
    case tls_CTRL_GET_MAX_CERT_LIST:
        return (long)s->max_cert_list;
    case tls_CTRL_SET_MAX_CERT_LIST:
        if (larg < 0)
            return 0;
        l = (long)s->max_cert_list;
        s->max_cert_list = (size_t)larg;
        return l;
    case tls_CTRL_SET_MAX_SEND_FRAGMENT:
        if (larg < 512 || larg > tls3_RT_MAX_PLAIN_LENGTH)
            return 0;
#ifndef OPENtls_NO_KTLS
        if (s->wbio != NULL && BIO_get_ktls_send(s->wbio))
            return 0;
#endif /* OPENtls_NO_KTLS */
        s->max_send_fragment = larg;
        if (s->max_send_fragment < s->split_send_fragment)
            s->split_send_fragment = s->max_send_fragment;
        return 1;
    case tls_CTRL_SET_SPLIT_SEND_FRAGMENT:
        if ((size_t)larg > s->max_send_fragment || larg == 0)
            return 0;
        s->split_send_fragment = larg;
        return 1;
    case tls_CTRL_SET_MAX_PIPELINES:
        if (larg < 1 || larg > tls_MAX_PIPELINES)
            return 0;
        s->max_pipelines = larg;
        if (larg > 1)
            RECORD_LAYER_set_read_ahead(&s->rlayer, 1);
        return 1;
    case tls_CTRL_GET_RI_SUPPORT:
        return s->s3.send_connection_binding;
    case tls_CTRL_CERT_FLAGS:
        return (s->cert->cert_flags |= larg);
    case tls_CTRL_CLEAR_CERT_FLAGS:
        return (s->cert->cert_flags &= ~larg);

    case tls_CTRL_GET_RAW_CIPHERLIST:
        if (parg) {
            if (s->s3.tmp.ciphers_raw == NULL)
                return 0;
            *(unsigned char **)parg = s->s3.tmp.ciphers_raw;
            return (int)s->s3.tmp.ciphers_rawlen;
        } else {
            return TLS_CIPHER_LEN;
        }
    case tls_CTRL_GET_EXTMS_SUPPORT:
        if (!s->session || tls_in_init(s) || otls_statem_get_in_handshake(s))
            return -1;
        if (s->session->flags & tls_SESS_FLAG_EXTMS)
            return 1;
        else
            return 0;
    case tls_CTRL_SET_MIN_PROTO_VERSION:
        return tls_check_allowed_versions(larg, s->max_proto_version)
               && tls_set_version_bound(s->ctx->method->version, (int)larg,
                                        &s->min_proto_version);
    case tls_CTRL_GET_MIN_PROTO_VERSION:
        return s->min_proto_version;
    case tls_CTRL_SET_MAX_PROTO_VERSION:
        return tls_check_allowed_versions(s->min_proto_version, larg)
               && tls_set_version_bound(s->ctx->method->version, (int)larg,
                                        &s->max_proto_version);
    case tls_CTRL_GET_MAX_PROTO_VERSION:
        return s->max_proto_version;
    default:
        return s->method->tls_ctrl(s, cmd, larg, parg);
    }
}

long tls_callback_ctrl(tls *s, int cmd, void (*fp) (void))
{
    switch (cmd) {
    case tls_CTRL_SET_MSG_CALLBACK:
        s->msg_callback = (void (*)
                           (int write_p, int version, int content_type,
                            const void *buf, size_t len, tls *tls,
                            void *arg))(fp);
        return 1;

    default:
        return s->method->tls_callback_ctrl(s, cmd, fp);
    }
}

LHASH_OF(tls_SESSION) *tls_CTX_sessions(tls_CTX *ctx)
{
    return ctx->sessions;
}

long tls_CTX_ctrl(tls_CTX *ctx, int cmd, long larg, void *parg)
{
    long l;
    /* For some cases with ctx == NULL perform syntax checks */
    if (ctx == NULL) {
        switch (cmd) {
#ifndef OPENtls_NO_EC
        case tls_CTRL_SET_GROUPS_LIST:
            return tls1_set_groups_list(NULL, NULL, parg);
#endif
        case tls_CTRL_SET_SIGALGS_LIST:
        case tls_CTRL_SET_CLIENT_SIGALGS_LIST:
            return tls1_set_sigalgs_list(NULL, parg, 0);
        default:
            return 0;
        }
    }

    switch (cmd) {
    case tls_CTRL_GET_READ_AHEAD:
        return ctx->read_ahead;
    case tls_CTRL_SET_READ_AHEAD:
        l = ctx->read_ahead;
        ctx->read_ahead = larg;
        return l;

    case tls_CTRL_SET_MSG_CALLBACK_ARG:
        ctx->msg_callback_arg = parg;
        return 1;

    case tls_CTRL_GET_MAX_CERT_LIST:
        return (long)ctx->max_cert_list;
    case tls_CTRL_SET_MAX_CERT_LIST:
        if (larg < 0)
            return 0;
        l = (long)ctx->max_cert_list;
        ctx->max_cert_list = (size_t)larg;
        return l;

    case tls_CTRL_SET_SESS_CACHE_SIZE:
        if (larg < 0)
            return 0;
        l = (long)ctx->session_cache_size;
        ctx->session_cache_size = (size_t)larg;
        return l;
    case tls_CTRL_GET_SESS_CACHE_SIZE:
        return (long)ctx->session_cache_size;
    case tls_CTRL_SET_SESS_CACHE_MODE:
        l = ctx->session_cache_mode;
        ctx->session_cache_mode = larg;
        return l;
    case tls_CTRL_GET_SESS_CACHE_MODE:
        return ctx->session_cache_mode;

    case tls_CTRL_SESS_NUMBER:
        return lh_tls_SESSION_num_items(ctx->sessions);
    case tls_CTRL_SESS_CONNECT:
        return tsan_load(&ctx->stats.sess_connect);
    case tls_CTRL_SESS_CONNECT_GOOD:
        return tsan_load(&ctx->stats.sess_connect_good);
    case tls_CTRL_SESS_CONNECT_RENEGOTIATE:
        return tsan_load(&ctx->stats.sess_connect_renegotiate);
    case tls_CTRL_SESS_ACCEPT:
        return tsan_load(&ctx->stats.sess_accept);
    case tls_CTRL_SESS_ACCEPT_GOOD:
        return tsan_load(&ctx->stats.sess_accept_good);
    case tls_CTRL_SESS_ACCEPT_RENEGOTIATE:
        return tsan_load(&ctx->stats.sess_accept_renegotiate);
    case tls_CTRL_SESS_HIT:
        return tsan_load(&ctx->stats.sess_hit);
    case tls_CTRL_SESS_CB_HIT:
        return tsan_load(&ctx->stats.sess_cb_hit);
    case tls_CTRL_SESS_MISSES:
        return tsan_load(&ctx->stats.sess_miss);
    case tls_CTRL_SESS_TIMEOUTS:
        return tsan_load(&ctx->stats.sess_timeout);
    case tls_CTRL_SESS_CACHE_FULL:
        return tsan_load(&ctx->stats.sess_cache_full);
    case tls_CTRL_MODE:
        return (ctx->mode |= larg);
    case tls_CTRL_CLEAR_MODE:
        return (ctx->mode &= ~larg);
    case tls_CTRL_SET_MAX_SEND_FRAGMENT:
        if (larg < 512 || larg > tls3_RT_MAX_PLAIN_LENGTH)
            return 0;
        ctx->max_send_fragment = larg;
        if (ctx->max_send_fragment < ctx->split_send_fragment)
            ctx->split_send_fragment = ctx->max_send_fragment;
        return 1;
    case tls_CTRL_SET_SPLIT_SEND_FRAGMENT:
        if ((size_t)larg > ctx->max_send_fragment || larg == 0)
            return 0;
        ctx->split_send_fragment = larg;
        return 1;
    case tls_CTRL_SET_MAX_PIPELINES:
        if (larg < 1 || larg > tls_MAX_PIPELINES)
            return 0;
        ctx->max_pipelines = larg;
        return 1;
    case tls_CTRL_CERT_FLAGS:
        return (ctx->cert->cert_flags |= larg);
    case tls_CTRL_CLEAR_CERT_FLAGS:
        return (ctx->cert->cert_flags &= ~larg);
    case tls_CTRL_SET_MIN_PROTO_VERSION:
        return tls_check_allowed_versions(larg, ctx->max_proto_version)
               && tls_set_version_bound(ctx->method->version, (int)larg,
                                        &ctx->min_proto_version);
    case tls_CTRL_GET_MIN_PROTO_VERSION:
        return ctx->min_proto_version;
    case tls_CTRL_SET_MAX_PROTO_VERSION:
        return tls_check_allowed_versions(ctx->min_proto_version, larg)
               && tls_set_version_bound(ctx->method->version, (int)larg,
                                        &ctx->max_proto_version);
    case tls_CTRL_GET_MAX_PROTO_VERSION:
        return ctx->max_proto_version;
    default:
        return ctx->method->tls_ctx_ctrl(ctx, cmd, larg, parg);
    }
}

long tls_CTX_callback_ctrl(tls_CTX *ctx, int cmd, void (*fp) (void))
{
    switch (cmd) {
    case tls_CTRL_SET_MSG_CALLBACK:
        ctx->msg_callback = (void (*)
                             (int write_p, int version, int content_type,
                              const void *buf, size_t len, tls *tls,
                              void *arg))(fp);
        return 1;

    default:
        return ctx->method->tls_ctx_callback_ctrl(ctx, cmd, fp);
    }
}

int tls_cipher_id_cmp(const tls_CIPHER *a, const tls_CIPHER *b)
{
    if (a->id > b->id)
        return 1;
    if (a->id < b->id)
        return -1;
    return 0;
}

int tls_cipher_ptr_id_cmp(const tls_CIPHER *const *ap,
                          const tls_CIPHER *const *bp)
{
    if ((*ap)->id > (*bp)->id)
        return 1;
    if ((*ap)->id < (*bp)->id)
        return -1;
    return 0;
}

/** return a STACK of the ciphers available for the tls and in order of
 * preference */
STACK_OF(tls_CIPHER) *tls_get_ciphers(const tls *s)
{
    if (s != NULL) {
        if (s->cipher_list != NULL) {
            return s->cipher_list;
        } else if ((s->ctx != NULL) && (s->ctx->cipher_list != NULL)) {
            return s->ctx->cipher_list;
        }
    }
    return NULL;
}

STACK_OF(tls_CIPHER) *tls_get_client_ciphers(const tls *s)
{
    if ((s == NULL) || !s->server)
        return NULL;
    return s->peer_ciphers;
}

STACK_OF(tls_CIPHER) *tls_get1_supported_ciphers(tls *s)
{
    STACK_OF(tls_CIPHER) *sk = NULL, *ciphers;
    int i;

    ciphers = tls_get_ciphers(s);
    if (!ciphers)
        return NULL;
    if (!tls_set_client_disabled(s))
        return NULL;
    for (i = 0; i < sk_tls_CIPHER_num(ciphers); i++) {
        const tls_CIPHER *c = sk_tls_CIPHER_value(ciphers, i);
        if (!tls_cipher_disabled(s, c, tls_SECOP_CIPHER_SUPPORTED, 0)) {
            if (!sk)
                sk = sk_tls_CIPHER_new_null();
            if (!sk)
                return NULL;
            if (!sk_tls_CIPHER_push(sk, c)) {
                sk_tls_CIPHER_free(sk);
                return NULL;
            }
        }
    }
    return sk;
}

/** return a STACK of the ciphers available for the tls and in order of
 * algorithm id */
STACK_OF(tls_CIPHER) *tls_get_ciphers_by_id(tls *s)
{
    if (s != NULL) {
        if (s->cipher_list_by_id != NULL) {
            return s->cipher_list_by_id;
        } else if ((s->ctx != NULL) && (s->ctx->cipher_list_by_id != NULL)) {
            return s->ctx->cipher_list_by_id;
        }
    }
    return NULL;
}

/** The old interface to get the same thing as tls_get_ciphers() */
const char *tls_get_cipher_list(const tls *s, int n)
{
    const tls_CIPHER *c;
    STACK_OF(tls_CIPHER) *sk;

    if (s == NULL)
        return NULL;
    sk = tls_get_ciphers(s);
    if ((sk == NULL) || (sk_tls_CIPHER_num(sk) <= n))
        return NULL;
    c = sk_tls_CIPHER_value(sk, n);
    if (c == NULL)
        return NULL;
    return c->name;
}

/** return a STACK of the ciphers available for the tls_CTX and in order of
 * preference */
STACK_OF(tls_CIPHER) *tls_CTX_get_ciphers(const tls_CTX *ctx)
{
    if (ctx != NULL)
        return ctx->cipher_list;
    return NULL;
}

/*
 * Distinguish between ciphers controlled by set_ciphersuite() and
 * set_cipher_list() when counting.
 */
static int cipher_list_tls12_num(STACK_OF(tls_CIPHER) *sk)
{
    int i, num = 0;
    const tls_CIPHER *c;

    if (sk == NULL)
        return 0;
    for (i = 0; i < sk_tls_CIPHER_num(sk); ++i) {
        c = sk_tls_CIPHER_value(sk, i);
        if (c->min_tls >= TLS1_3_VERSION)
            continue;
        num++;
    }
    return num;
}

/** specify the ciphers to be used by default by the tls_CTX */
int tls_CTX_set_cipher_list(tls_CTX *ctx, const char *str)
{
    STACK_OF(tls_CIPHER) *sk;

    sk = tls_create_cipher_list(ctx->method, ctx->tls13_ciphersuites,
                                &ctx->cipher_list, &ctx->cipher_list_by_id, str,
                                ctx->cert);
    /*
     * tls_create_cipher_list may return an empty stack if it was unable to
     * find a cipher matching the given rule string (for example if the rule
     * string specifies a cipher which has been disabled). This is not an
     * error as far as tls_create_cipher_list is concerned, and hence
     * ctx->cipher_list and ctx->cipher_list_by_id has been updated.
     */
    if (sk == NULL)
        return 0;
    else if (cipher_list_tls12_num(sk) == 0) {
        tlserr(tls_F_tls_CTX_SET_CIPHER_LIST, tls_R_NO_CIPHER_MATCH);
        return 0;
    }
    return 1;
}

/** specify the ciphers to be used by the tls */
int tls_set_cipher_list(tls *s, const char *str)
{
    STACK_OF(tls_CIPHER) *sk;

    sk = tls_create_cipher_list(s->ctx->method, s->tls13_ciphersuites,
                                &s->cipher_list, &s->cipher_list_by_id, str,
                                s->cert);
    /* see comment in tls_CTX_set_cipher_list */
    if (sk == NULL)
        return 0;
    else if (cipher_list_tls12_num(sk) == 0) {
        tlserr(tls_F_tls_SET_CIPHER_LIST, tls_R_NO_CIPHER_MATCH);
        return 0;
    }
    return 1;
}

char *tls_get_shared_ciphers(const tls *s, char *buf, int size)
{
    char *p;
    STACK_OF(tls_CIPHER) *clntsk, *srvrsk;
    const tls_CIPHER *c;
    int i;

    if (!s->server
            || s->peer_ciphers == NULL
            || size < 2)
        return NULL;

    p = buf;
    clntsk = s->peer_ciphers;
    srvrsk = tls_get_ciphers(s);
    if (clntsk == NULL || srvrsk == NULL)
        return NULL;

    if (sk_tls_CIPHER_num(clntsk) == 0 || sk_tls_CIPHER_num(srvrsk) == 0)
        return NULL;

    for (i = 0; i < sk_tls_CIPHER_num(clntsk); i++) {
        int n;

        c = sk_tls_CIPHER_value(clntsk, i);
        if (sk_tls_CIPHER_find(srvrsk, c) < 0)
            continue;

        n = strlen(c->name);
        if (n + 1 > size) {
            if (p != buf)
                --p;
            *p = '\0';
            return buf;
        }
        strcpy(p, c->name);
        p += n;
        *(p++) = ':';
        size -= n + 1;
    }
    p[-1] = '\0';
    return buf;
}

/** return a servername extension value if provided in Client Hello, or NULL.
 * So far, only host_name types are defined (RFC 3546).
 */

const char *tls_get_servername(const tls *s, const int type)
{
    if (type != TLSEXT_NAMETYPE_host_name)
        return NULL;

    /*
     * SNI is not negotiated in pre-TLS-1.3 resumption flows, so fake up an
     * SNI value to return if we are resuming/resumed.  N.B. that we still
     * call the relevant callbacks for such resumption flows, and callbacks
     * might error out if there is not a SNI value available.
     */
    if (s->hit)
        return s->session->ext.hostname;
    return s->ext.hostname;
}

int tls_get_servername_type(const tls *s)
{
    if (s->session
        && (!s->ext.hostname ? s->session->
            ext.hostname : s->ext.hostname))
        return TLSEXT_NAMETYPE_host_name;
    return -1;
}

/*
 * tls_select_next_proto implements the standard protocol selection. It is
 * expected that this function is called from the callback set by
 * tls_CTX_set_next_proto_select_cb. The protocol data is assumed to be a
 * vector of 8-bit, length prefixed byte strings. The length byte itself is
 * not included in the length. A byte string of length 0 is invalid. No byte
 * string may be truncated. The current, but experimental algorithm for
 * selecting the protocol is: 1) If the server doesn't support NPN then this
 * is indicated to the callback. In this case, the client application has to
 * abort the connection or have a default application level protocol. 2) If
 * the server supports NPN, but advertises an empty list then the client
 * selects the first protocol in its list, but indicates via the API that this
 * fallback case was enacted. 3) Otherwise, the client finds the first
 * protocol in the server's list that it supports and selects this protocol.
 * This is because it's assumed that the server has better information about
 * which protocol a client should use. 4) If the client doesn't support any
 * of the server's advertised protocols, then this is treated the same as
 * case 2. It returns either OPENtls_NPN_NEGOTIATED if a common protocol was
 * found, or OPENtls_NPN_NO_OVERLAP if the fallback case was reached.
 */
int tls_select_next_proto(unsigned char **out, unsigned char *outlen,
                          const unsigned char *server,
                          unsigned int server_len,
                          const unsigned char *client, unsigned int client_len)
{
    unsigned int i, j;
    const unsigned char *result;
    int status = OPENtls_NPN_UNSUPPORTED;

    /*
     * For each protocol in server preference order, see if we support it.
     */
    for (i = 0; i < server_len;) {
        for (j = 0; j < client_len;) {
            if (server[i] == client[j] &&
                memcmp(&server[i + 1], &client[j + 1], server[i]) == 0) {
                /* We found a match */
                result = &server[i];
                status = OPENtls_NPN_NEGOTIATED;
                goto found;
            }
            j += client[j];
            j++;
        }
        i += server[i];
        i++;
    }

    /* There's no overlap between our protocols and the server's list. */
    result = client;
    status = OPENtls_NPN_NO_OVERLAP;

 found:
    *out = (unsigned char *)result + 1;
    *outlen = result[0];
    return status;
}

#ifndef OPENtls_NO_NEXTPROTONEG
/*
 * tls_get0_next_proto_negotiated sets *data and *len to point to the
 * client's requested protocol for this connection and returns 0. If the
 * client didn't request any protocol, then *data is set to NULL. Note that
 * the client can request any protocol it chooses. The value returned from
 * this function need not be a member of the list of supported protocols
 * provided by the callback.
 */
void tls_get0_next_proto_negotiated(const tls *s, const unsigned char **data,
                                    unsigned *len)
{
    *data = s->ext.npn;
    if (*data == NULL) {
        *len = 0;
    } else {
        *len = (unsigned int)s->ext.npn_len;
    }
}

/*
 * tls_CTX_set_npn_advertised_cb sets a callback that is called when
 * a TLS server needs a list of supported protocols for Next Protocol
 * Negotiation. The returned list must be in wire format.  The list is
 * returned by setting |out| to point to it and |outlen| to its length. This
 * memory will not be modified, but one should assume that the tls* keeps a
 * reference to it. The callback should return tls_TLSEXT_ERR_OK if it
 * wishes to advertise. Otherwise, no such extension will be included in the
 * ServerHello.
 */
void tls_CTX_set_npn_advertised_cb(tls_CTX *ctx,
                                   tls_CTX_npn_advertised_cb_func cb,
                                   void *arg)
{
    ctx->ext.npn_advertised_cb = cb;
    ctx->ext.npn_advertised_cb_arg = arg;
}

/*
 * tls_CTX_set_next_proto_select_cb sets a callback that is called when a
 * client needs to select a protocol from the server's provided list. |out|
 * must be set to point to the selected protocol (which may be within |in|).
 * The length of the protocol name must be written into |outlen|. The
 * server's advertised protocols are provided in |in| and |inlen|. The
 * callback can assume that |in| is syntactically valid. The client must
 * select a protocol. It is fatal to the connection if this callback returns
 * a value other than tls_TLSEXT_ERR_OK.
 */
void tls_CTX_set_npn_select_cb(tls_CTX *ctx,
                               tls_CTX_npn_select_cb_func cb,
                               void *arg)
{
    ctx->ext.npn_select_cb = cb;
    ctx->ext.npn_select_cb_arg = arg;
}
#endif

/*
 * tls_CTX_set_alpn_protos sets the ALPN protocol list on |ctx| to |protos|.
 * |protos| must be in wire-format (i.e. a series of non-empty, 8-bit
 * length-prefixed strings). Returns 0 on success.
 */
int tls_CTX_set_alpn_protos(tls_CTX *ctx, const unsigned char *protos,
                            unsigned int protos_len)
{
    OPENtls_free(ctx->ext.alpn);
    ctx->ext.alpn = OPENtls_memdup(protos, protos_len);
    if (ctx->ext.alpn == NULL) {
        tlserr(tls_F_tls_CTX_SET_ALPN_PROTOS, ERR_R_MALLOC_FAILURE);
        return 1;
    }
    ctx->ext.alpn_len = protos_len;

    return 0;
}

/*
 * tls_set_alpn_protos sets the ALPN protocol list on |tls| to |protos|.
 * |protos| must be in wire-format (i.e. a series of non-empty, 8-bit
 * length-prefixed strings). Returns 0 on success.
 */
int tls_set_alpn_protos(tls *tls, const unsigned char *protos,
                        unsigned int protos_len)
{
    OPENtls_free(tls->ext.alpn);
    tls->ext.alpn = OPENtls_memdup(protos, protos_len);
    if (tls->ext.alpn == NULL) {
        tlserr(tls_F_tls_SET_ALPN_PROTOS, ERR_R_MALLOC_FAILURE);
        return 1;
    }
    tls->ext.alpn_len = protos_len;

    return 0;
}

/*
 * tls_CTX_set_alpn_select_cb sets a callback function on |ctx| that is
 * called during ClientHello processing in order to select an ALPN protocol
 * from the client's list of offered protocols.
 */
void tls_CTX_set_alpn_select_cb(tls_CTX *ctx,
                                tls_CTX_alpn_select_cb_func cb,
                                void *arg)
{
    ctx->ext.alpn_select_cb = cb;
    ctx->ext.alpn_select_cb_arg = arg;
}

/*
 * tls_get0_alpn_selected gets the selected ALPN protocol (if any) from |tls|.
 * On return it sets |*data| to point to |*len| bytes of protocol name
 * (not including the leading length-prefix byte). If the server didn't
 * respond with a negotiated protocol then |*len| will be zero.
 */
void tls_get0_alpn_selected(const tls *tls, const unsigned char **data,
                            unsigned int *len)
{
    *data = tls->s3.alpn_selected;
    if (*data == NULL)
        *len = 0;
    else
        *len = (unsigned int)tls->s3.alpn_selected_len;
}

int tls_export_keying_material(tls *s, unsigned char *out, size_t olen,
                               const char *label, size_t llen,
                               const unsigned char *context, size_t contextlen,
                               int use_context)
{
    if (s->version < TLS1_VERSION && s->version != DTLS1_BAD_VER)
        return -1;

    return s->method->tls3_enc->export_keying_material(s, out, olen, label,
                                                       llen, context,
                                                       contextlen, use_context);
}

int tls_export_keying_material_early(tls *s, unsigned char *out, size_t olen,
                                     const char *label, size_t llen,
                                     const unsigned char *context,
                                     size_t contextlen)
{
    if (s->version != TLS1_3_VERSION)
        return 0;

    return tls13_export_keying_material_early(s, out, olen, label, llen,
                                              context, contextlen);
}

static unsigned long tls_session_hash(const tls_SESSION *a)
{
    const unsigned char *session_id = a->session_id;
    unsigned long l;
    unsigned char tmp_storage[4];

    if (a->session_id_length < sizeof(tmp_storage)) {
        memset(tmp_storage, 0, sizeof(tmp_storage));
        memcpy(tmp_storage, a->session_id, a->session_id_length);
        session_id = tmp_storage;
    }

    l = (unsigned long)
        ((unsigned long)session_id[0]) |
        ((unsigned long)session_id[1] << 8L) |
        ((unsigned long)session_id[2] << 16L) |
        ((unsigned long)session_id[3] << 24L);
    return l;
}

/*
 * NB: If this function (or indeed the hash function which uses a sort of
 * coarser function than this one) is changed, ensure
 * tls_CTX_has_matching_session_id() is checked accordingly. It relies on
 * being able to construct an tls_SESSION that will collide with any existing
 * session with a matching session ID.
 */
static int tls_session_cmp(const tls_SESSION *a, const tls_SESSION *b)
{
    if (a->tls_version != b->tls_version)
        return 1;
    if (a->session_id_length != b->session_id_length)
        return 1;
    return memcmp(a->session_id, b->session_id, a->session_id_length);
}

/*
 * These wrapper functions should remain rather than redeclaring
 * tls_SESSION_hash and tls_SESSION_cmp for void* types and casting each
 * variable. The reason is that the functions aren't static, they're exposed
 * via tls.h.
 */

tls_CTX *tls_CTX_new(const tls_METHOD *meth)
{
    tls_CTX *ret = NULL;

    if (meth == NULL) {
        tlserr(tls_F_tls_CTX_NEW, tls_R_NULL_tls_METHOD_PASSED);
        return NULL;
    }

    if (!OPENtls_init_tls(OPENtls_INIT_LOAD_tls_STRINGS, NULL))
        return NULL;

    if (tls_get_ex_data_X509_STORE_CTX_idx() < 0) {
        tlserr(tls_F_tls_CTX_NEW, tls_R_X509_VERIFICATION_SETUP_PROBLEMS);
        goto err;
    }
    ret = OPENtls_zalloc(sizeof(*ret));
    if (ret == NULL)
        goto err;

    ret->method = meth;
    ret->min_proto_version = 0;
    ret->max_proto_version = 0;
    ret->mode = tls_MODE_AUTO_RETRY;
    ret->session_cache_mode = tls_SESS_CACHE_SERVER;
    ret->session_cache_size = tls_SESSION_CACHE_MAX_SIZE_DEFAULT;
    /* We take the system default. */
    ret->session_timeout = meth->get_timeout();
    ret->references = 1;
    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        tlserr(tls_F_tls_CTX_NEW, ERR_R_MALLOC_FAILURE);
        OPENtls_free(ret);
        return NULL;
    }
    ret->max_cert_list = tls_MAX_CERT_LIST_DEFAULT;
    ret->verify_mode = tls_VERIFY_NONE;
    if ((ret->cert = tls_cert_new()) == NULL)
        goto err;

    ret->sessions = lh_tls_SESSION_new(tls_session_hash, tls_session_cmp);
    if (ret->sessions == NULL)
        goto err;
    ret->cert_store = X509_STORE_new();
    if (ret->cert_store == NULL)
        goto err;
#ifndef OPENtls_NO_CT
    ret->ctlog_store = CTLOG_STORE_new();
    if (ret->ctlog_store == NULL)
        goto err;
#endif

    if (!tls_CTX_set_ciphersuites(ret, Otls_default_ciphersuites()))
        goto err;

    if (!tls_create_cipher_list(ret->method,
                                ret->tls13_ciphersuites,
                                &ret->cipher_list, &ret->cipher_list_by_id,
                                Otls_default_cipher_list(), ret->cert)
        || sk_tls_CIPHER_num(ret->cipher_list) <= 0) {
        tlserr(tls_F_tls_CTX_NEW, tls_R_LIBRARY_HAS_NO_CIPHERS);
        goto err2;
    }

    ret->param = X509_VERIFY_PARAM_new();
    if (ret->param == NULL)
        goto err;

    if ((ret->md5 = EVP_get_digestbyname("tls3-md5")) == NULL) {
        tlserr(tls_F_tls_CTX_NEW, tls_R_UNABLE_TO_LOAD_tls3_MD5_ROUTINES);
        goto err2;
    }
    if ((ret->sha1 = EVP_get_digestbyname("tls3-sha1")) == NULL) {
        tlserr(tls_F_tls_CTX_NEW, tls_R_UNABLE_TO_LOAD_tls3_SHA1_ROUTINES);
        goto err2;
    }

    if ((ret->ca_names = sk_X509_NAME_new_null()) == NULL)
        goto err;

    if ((ret->client_ca_names = sk_X509_NAME_new_null()) == NULL)
        goto err;

    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_tls_CTX, ret, &ret->ex_data))
        goto err;

    if ((ret->ext.secure = OPENtls_secure_zalloc(sizeof(*ret->ext.secure))) == NULL)
        goto err;

    /* No compression for DTLS */
    if (!(meth->tls3_enc->enc_flags & tls_ENC_FLAG_DTLS))
        ret->comp_methods = tls_COMP_get_compression_methods();

    ret->max_send_fragment = tls3_RT_MAX_PLAIN_LENGTH;
    ret->split_send_fragment = tls3_RT_MAX_PLAIN_LENGTH;

    /* Setup RFC5077 ticket keys */
    if ((RAND_bytes(ret->ext.tick_key_name,
                    sizeof(ret->ext.tick_key_name)) <= 0)
        || (RAND_priv_bytes(ret->ext.secure->tick_hmac_key,
                       sizeof(ret->ext.secure->tick_hmac_key)) <= 0)
        || (RAND_priv_bytes(ret->ext.secure->tick_aes_key,
                       sizeof(ret->ext.secure->tick_aes_key)) <= 0))
        ret->options |= tls_OP_NO_TICKET;

    if (RAND_priv_bytes(ret->ext.cookie_hmac_key,
                   sizeof(ret->ext.cookie_hmac_key)) <= 0)
        goto err;

#ifndef OPENtls_NO_SRP
    if (!tls_CTX_SRP_CTX_init(ret))
        goto err;
#endif
#ifndef OPENtls_NO_ENGINE
# ifdef OPENtls_tls_CLIENT_ENGINE_AUTO
#  define eng_strx(x)     #x
#  define eng_str(x)      eng_strx(x)
    /* Use specific client engine automatically... ignore errors */
    {
        ENGINE *eng;
        eng = ENGINE_by_id(eng_str(OPENtls_tls_CLIENT_ENGINE_AUTO));
        if (!eng) {
            ERR_clear_error();
            ENGINE_load_builtin_engines();
            eng = ENGINE_by_id(eng_str(OPENtls_tls_CLIENT_ENGINE_AUTO));
        }
        if (!eng || !tls_CTX_set_client_cert_engine(ret, eng))
            ERR_clear_error();
    }
# endif
#endif
    /*
     * Default is to connect to non-RI servers. When RI is more widely
     * deployed might change this.
     */
    ret->options |= tls_OP_LEGACY_SERVER_CONNECT;
    /*
     * Disable compression by default to prevent CRIME. Applications can
     * re-enable compression by configuring
     * tls_CTX_clear_options(ctx, tls_OP_NO_COMPRESSION);
     * or by using the tls_CONF library. Similarly we also enable TLSv1.3
     * middlebox compatibility by default. This may be disabled by default in
     * a later Opentls version.
     */
    ret->options |= tls_OP_NO_COMPRESSION | tls_OP_ENABLE_MIDDLEBOX_COMPAT;

    ret->ext.status_type = TLSEXT_STATUSTYPE_nothing;

    /*
     * We cannot usefully set a default max_early_data here (which gets
     * propagated in tls_new(), for the following reason: setting the
     * tls field causes tls_construct_stoc_early_data() to tell the
     * client that early data will be accepted when constructing a TLS 1.3
     * session ticket, and the client will accordingly send us early data
     * when using that ticket (if the client has early data to send).
     * However, in order for the early data to actually be consumed by
     * the application, the application must also have calls to
     * tls_read_early_data(); otherwise we'll just skip past the early data
     * and ignore it.  So, since the application must add calls to
     * tls_read_early_data(), we also require them to add
     * calls to tls_CTX_set_max_early_data() in order to use early data,
     * eliminating the bandwidth-wasting early data in the case described
     * above.
     */
    ret->max_early_data = 0;

    /*
     * Default recv_max_early_data is a fully loaded single record. Could be
     * split across multiple records in practice. We set this differently to
     * max_early_data so that, in the default case, we do not advertise any
     * support for early_data, but if a client were to send us some (e.g.
     * because of an old, stale ticket) then we will tolerate it and skip over
     * it.
     */
    ret->recv_max_early_data = tls3_RT_MAX_PLAIN_LENGTH;

    /* By default we send two session tickets automatically in TLSv1.3 */
    ret->num_tickets = 2;

    tls_ctx_system_config(ret);

    return ret;
 err:
    tlserr(tls_F_tls_CTX_NEW, ERR_R_MALLOC_FAILURE);
 err2:
    tls_CTX_free(ret);
    return NULL;
}

int tls_CTX_up_ref(tls_CTX *ctx)
{
    int i;

    if (CRYPTO_UP_REF(&ctx->references, &i, ctx->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("tls_CTX", ctx);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

void tls_CTX_free(tls_CTX *a)
{
    int i;

    if (a == NULL)
        return;

    CRYPTO_DOWN_REF(&a->references, &i, a->lock);
    REF_PRINT_COUNT("tls_CTX", a);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    X509_VERIFY_PARAM_free(a->param);
    dane_ctx_final(&a->dane);

    /*
     * Free internal session cache. However: the remove_cb() may reference
     * the ex_data of tls_CTX, thus the ex_data store can only be removed
     * after the sessions were flushed.
     * As the ex_data handling routines might also touch the session cache,
     * the most secure solution seems to be: empty (flush) the cache, then
     * free ex_data, then finally free the cache.
     * (See ticket [opentls.org #212].)
     */
    if (a->sessions != NULL)
        tls_CTX_flush_sessions(a, 0);

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_tls_CTX, a, &a->ex_data);
    lh_tls_SESSION_free(a->sessions);
    X509_STORE_free(a->cert_store);
#ifndef OPENtls_NO_CT
    CTLOG_STORE_free(a->ctlog_store);
#endif
    sk_tls_CIPHER_free(a->cipher_list);
    sk_tls_CIPHER_free(a->cipher_list_by_id);
    sk_tls_CIPHER_free(a->tls13_ciphersuites);
    tls_cert_free(a->cert);
    sk_X509_NAME_pop_free(a->ca_names, X509_NAME_free);
    sk_X509_NAME_pop_free(a->client_ca_names, X509_NAME_free);
    sk_X509_pop_free(a->extra_certs, X509_free);
    a->comp_methods = NULL;
#ifndef OPENtls_NO_SRTP
    sk_SRTP_PROTECTION_PROFILE_free(a->srtp_profiles);
#endif
#ifndef OPENtls_NO_SRP
    tls_CTX_SRP_CTX_free(a);
#endif
#ifndef OPENtls_NO_ENGINE
    ENGINE_finish(a->client_cert_engine);
#endif

#ifndef OPENtls_NO_EC
    OPENtls_free(a->ext.ecpointformats);
#endif
    OPENtls_free(a->ext.supportedgroups);
    OPENtls_free(a->ext.alpn);
    OPENtls_secure_free(a->ext.secure);

    CRYPTO_THREAD_lock_free(a->lock);

    OPENtls_free(a);
}

void tls_CTX_set_default_passwd_cb(tls_CTX *ctx, pem_password_cb *cb)
{
    ctx->default_passwd_callback = cb;
}

void tls_CTX_set_default_passwd_cb_userdata(tls_CTX *ctx, void *u)
{
    ctx->default_passwd_callback_userdata = u;
}

pem_password_cb *tls_CTX_get_default_passwd_cb(tls_CTX *ctx)
{
    return ctx->default_passwd_callback;
}

void *tls_CTX_get_default_passwd_cb_userdata(tls_CTX *ctx)
{
    return ctx->default_passwd_callback_userdata;
}

void tls_set_default_passwd_cb(tls *s, pem_password_cb *cb)
{
    s->default_passwd_callback = cb;
}

void tls_set_default_passwd_cb_userdata(tls *s, void *u)
{
    s->default_passwd_callback_userdata = u;
}

pem_password_cb *tls_get_default_passwd_cb(tls *s)
{
    return s->default_passwd_callback;
}

void *tls_get_default_passwd_cb_userdata(tls *s)
{
    return s->default_passwd_callback_userdata;
}

void tls_CTX_set_cert_verify_callback(tls_CTX *ctx,
                                      int (*cb) (X509_STORE_CTX *, void *),
                                      void *arg)
{
    ctx->app_verify_callback = cb;
    ctx->app_verify_arg = arg;
}

void tls_CTX_set_verify(tls_CTX *ctx, int mode,
                        int (*cb) (int, X509_STORE_CTX *))
{
    ctx->verify_mode = mode;
    ctx->default_verify_callback = cb;
}

void tls_CTX_set_verify_depth(tls_CTX *ctx, int depth)
{
    X509_VERIFY_PARAM_set_depth(ctx->param, depth);
}

void tls_CTX_set_cert_cb(tls_CTX *c, int (*cb) (tls *tls, void *arg), void *arg)
{
    tls_cert_set_cert_cb(c->cert, cb, arg);
}

void tls_set_cert_cb(tls *s, int (*cb) (tls *tls, void *arg), void *arg)
{
    tls_cert_set_cert_cb(s->cert, cb, arg);
}

void tls_set_masks(tls *s)
{
    CERT *c = s->cert;
    uint32_t *pvalid = s->s3.tmp.valid_flags;
    int rsa_enc, rsa_sign, dh_tmp, dsa_sign;
    unsigned long mask_k, mask_a;
#ifndef OPENtls_NO_EC
    int have_ecc_cert, ecdsa_ok;
#endif
    if (c == NULL)
        return;

#ifndef OPENtls_NO_DH
    dh_tmp = (c->dh_tmp != NULL || c->dh_tmp_cb != NULL || c->dh_tmp_auto);
#else
    dh_tmp = 0;
#endif

    rsa_enc = pvalid[tls_PKEY_RSA] & CERT_PKEY_VALID;
    rsa_sign = pvalid[tls_PKEY_RSA] & CERT_PKEY_VALID;
    dsa_sign = pvalid[tls_PKEY_DSA_SIGN] & CERT_PKEY_VALID;
#ifndef OPENtls_NO_EC
    have_ecc_cert = pvalid[tls_PKEY_ECC] & CERT_PKEY_VALID;
#endif
    mask_k = 0;
    mask_a = 0;

    Otls_TRACE4(TLS_CIPHER, "dh_tmp=%d rsa_enc=%d rsa_sign=%d dsa_sign=%d\n",
               dh_tmp, rsa_enc, rsa_sign, dsa_sign);

#ifndef OPENtls_NO_GOST
    if (tls_has_cert(s, tls_PKEY_GOST12_512)) {
        mask_k |= tls_kGOST;
        mask_a |= tls_aGOST12;
    }
    if (tls_has_cert(s, tls_PKEY_GOST12_256)) {
        mask_k |= tls_kGOST;
        mask_a |= tls_aGOST12;
    }
    if (tls_has_cert(s, tls_PKEY_GOST01)) {
        mask_k |= tls_kGOST;
        mask_a |= tls_aGOST01;
    }
#endif

    if (rsa_enc)
        mask_k |= tls_kRSA;

    if (dh_tmp)
        mask_k |= tls_kDHE;

    /*
     * If we only have an RSA-PSS certificate allow RSA authentication
     * if TLS 1.2 and peer supports it.
     */

    if (rsa_enc || rsa_sign || (tls_has_cert(s, tls_PKEY_RSA_PSS_SIGN)
                && pvalid[tls_PKEY_RSA_PSS_SIGN] & CERT_PKEY_EXPLICIT_SIGN
                && TLS1_get_version(s) == TLS1_2_VERSION))
        mask_a |= tls_aRSA;

    if (dsa_sign) {
        mask_a |= tls_aDSS;
    }

    mask_a |= tls_aNULL;

    /*
     * An ECC certificate may be usable for ECDH and/or ECDSA cipher suites
     * depending on the key usage extension.
     */
#ifndef OPENtls_NO_EC
    if (have_ecc_cert) {
        uint32_t ex_kusage;
        ex_kusage = X509_get_key_usage(c->pkeys[tls_PKEY_ECC].x509);
        ecdsa_ok = ex_kusage & X509v3_KU_DIGITAL_SIGNATURE;
        if (!(pvalid[tls_PKEY_ECC] & CERT_PKEY_SIGN))
            ecdsa_ok = 0;
        if (ecdsa_ok)
            mask_a |= tls_aECDSA;
    }
    /* Allow Ed25519 for TLS 1.2 if peer supports it */
    if (!(mask_a & tls_aECDSA) && tls_has_cert(s, tls_PKEY_ED25519)
            && pvalid[tls_PKEY_ED25519] & CERT_PKEY_EXPLICIT_SIGN
            && TLS1_get_version(s) == TLS1_2_VERSION)
            mask_a |= tls_aECDSA;

    /* Allow Ed448 for TLS 1.2 if peer supports it */
    if (!(mask_a & tls_aECDSA) && tls_has_cert(s, tls_PKEY_ED448)
            && pvalid[tls_PKEY_ED448] & CERT_PKEY_EXPLICIT_SIGN
            && TLS1_get_version(s) == TLS1_2_VERSION)
            mask_a |= tls_aECDSA;
#endif

#ifndef OPENtls_NO_EC
    mask_k |= tls_kECDHE;
#endif

#ifndef OPENtls_NO_PSK
    mask_k |= tls_kPSK;
    mask_a |= tls_aPSK;
    if (mask_k & tls_kRSA)
        mask_k |= tls_kRSAPSK;
    if (mask_k & tls_kDHE)
        mask_k |= tls_kDHEPSK;
    if (mask_k & tls_kECDHE)
        mask_k |= tls_kECDHEPSK;
#endif

    s->s3.tmp.mask_k = mask_k;
    s->s3.tmp.mask_a = mask_a;
}

#ifndef OPENtls_NO_EC

int tls_check_srvr_ecc_cert_and_alg(X509 *x, tls *s)
{
    if (s->s3.tmp.new_cipher->algorithm_auth & tls_aECDSA) {
        /* key usage, if present, must allow signing */
        if (!(X509_get_key_usage(x) & X509v3_KU_DIGITAL_SIGNATURE)) {
            tlserr(tls_F_tls_CHECK_SRVR_ECC_CERT_AND_ALG,
                   tls_R_ECC_CERT_NOT_FOR_SIGNING);
            return 0;
        }
    }
    return 1;                   /* all checks are ok */
}

#endif

int tls_get_server_cert_serverinfo(tls *s, const unsigned char **serverinfo,
                                   size_t *serverinfo_length)
{
    CERT_PKEY *cpk = s->s3.tmp.cert;
    *serverinfo_length = 0;

    if (cpk == NULL || cpk->serverinfo == NULL)
        return 0;

    *serverinfo = cpk->serverinfo;
    *serverinfo_length = cpk->serverinfo_length;
    return 1;
}

void tls_update_cache(tls *s, int mode)
{
    int i;

    /*
     * If the session_id_length is 0, we are not supposed to cache it, and it
     * would be rather hard to do anyway :-)
     */
    if (s->session->session_id_length == 0)
        return;

    /*
     * If sid_ctx_length is 0 there is no specific application context
     * associated with this session, so when we try to resume it and
     * tls_VERIFY_PEER is requested to verify the client identity, we have no
     * indication that this is actually a session for the proper application
     * context, and the *handshake* will fail, not just the resumption attempt.
     * Do not cache (on the server) these sessions that are not resumable
     * (clients can set tls_VERIFY_PEER without needing a sid_ctx set).
     */
    if (s->server && s->session->sid_ctx_length == 0
            && (s->verify_mode & tls_VERIFY_PEER) != 0)
        return;

    i = s->session_ctx->session_cache_mode;
    if ((i & mode) != 0
        && (!s->hit || tls_IS_TLS13(s))) {
        /*
         * Add the session to the internal cache. In server side TLSv1.3 we
         * normally don't do this because by default it's a full stateless ticket
         * with only a dummy session id so there is no reason to cache it,
         * unless:
         * - we are doing early_data, in which case we cache so that we can
         *   detect replays
         * - the application has set a remove_session_cb so needs to know about
         *   session timeout events
         * - tls_OP_NO_TICKET is set in which case it is a stateful ticket
         */
        if ((i & tls_SESS_CACHE_NO_INTERNAL_STORE) == 0
                && (!tls_IS_TLS13(s)
                    || !s->server
                    || (s->max_early_data > 0
                        && (s->options & tls_OP_NO_ANTI_REPLAY) == 0)
                    || s->session_ctx->remove_session_cb != NULL
                    || (s->options & tls_OP_NO_TICKET) != 0))
            tls_CTX_add_session(s->session_ctx, s->session);

        /*
         * Add the session to the external cache. We do this even in server side
         * TLSv1.3 without early data because some applications just want to
         * know about the creation of a session and aren't doing a full cache.
         */
        if (s->session_ctx->new_session_cb != NULL) {
            tls_SESSION_up_ref(s->session);
            if (!s->session_ctx->new_session_cb(s, s->session))
                tls_SESSION_free(s->session);
        }
    }

    /* auto flush every 255 connections */
    if ((!(i & tls_SESS_CACHE_NO_AUTO_CLEAR)) && ((i & mode) == mode)) {
        TSAN_QUALIFIER int *stat;
        if (mode & tls_SESS_CACHE_CLIENT)
            stat = &s->session_ctx->stats.sess_connect_good;
        else
            stat = &s->session_ctx->stats.sess_accept_good;
        if ((tsan_load(stat) & 0xff) == 0xff)
            tls_CTX_flush_sessions(s->session_ctx, (unsigned long)time(NULL));
    }
}

const tls_METHOD *tls_CTX_get_tls_method(const tls_CTX *ctx)
{
    return ctx->method;
}

const tls_METHOD *tls_get_tls_method(const tls *s)
{
    return s->method;
}

int tls_set_tls_method(tls *s, const tls_METHOD *meth)
{
    int ret = 1;

    if (s->method != meth) {
        const tls_METHOD *sm = s->method;
        int (*hf) (tls *) = s->handshake_func;

        if (sm->version == meth->version)
            s->method = meth;
        else {
            sm->tls_free(s);
            s->method = meth;
            ret = s->method->tls_new(s);
        }

        if (hf == sm->tls_connect)
            s->handshake_func = meth->tls_connect;
        else if (hf == sm->tls_accept)
            s->handshake_func = meth->tls_accept;
    }
    return ret;
}

int tls_get_error(const tls *s, int i)
{
    int reason;
    unsigned long l;
    BIO *bio;

    if (i > 0)
        return tls_ERROR_NONE;

    /*
     * Make things return tls_ERROR_SYSCALL when doing tls_do_handshake etc,
     * where we do encode the error
     */
    if ((l = ERR_peek_error()) != 0) {
        if (ERR_GET_LIB(l) == ERR_LIB_SYS)
            return tls_ERROR_SYSCALL;
        else
            return tls_ERROR_tls;
    }

    if (tls_want_read(s)) {
        bio = tls_get_rbio(s);
        if (BIO_should_read(bio))
            return tls_ERROR_WANT_READ;
        else if (BIO_should_write(bio))
            /*
             * This one doesn't make too much sense ... We never try to write
             * to the rbio, and an application program where rbio and wbio
             * are separate couldn't even know what it should wait for.
             * However if we ever set s->rwstate incorrectly (so that we have
             * tls_want_read(s) instead of tls_want_write(s)) and rbio and
             * wbio *are* the same, this test works around that bug; so it
             * might be safer to keep it.
             */
            return tls_ERROR_WANT_WRITE;
        else if (BIO_should_io_special(bio)) {
            reason = BIO_get_retry_reason(bio);
            if (reason == BIO_RR_CONNECT)
                return tls_ERROR_WANT_CONNECT;
            else if (reason == BIO_RR_ACCEPT)
                return tls_ERROR_WANT_ACCEPT;
            else
                return tls_ERROR_SYSCALL; /* unknown */
        }
    }

    if (tls_want_write(s)) {
        /* Access wbio directly - in order to use the buffered bio if present */
        bio = s->wbio;
        if (BIO_should_write(bio))
            return tls_ERROR_WANT_WRITE;
        else if (BIO_should_read(bio))
            /*
             * See above (tls_want_read(s) with BIO_should_write(bio))
             */
            return tls_ERROR_WANT_READ;
        else if (BIO_should_io_special(bio)) {
            reason = BIO_get_retry_reason(bio);
            if (reason == BIO_RR_CONNECT)
                return tls_ERROR_WANT_CONNECT;
            else if (reason == BIO_RR_ACCEPT)
                return tls_ERROR_WANT_ACCEPT;
            else
                return tls_ERROR_SYSCALL;
        }
    }
    if (tls_want_x509_lookup(s))
        return tls_ERROR_WANT_X509_LOOKUP;
    if (tls_want_async(s))
        return tls_ERROR_WANT_ASYNC;
    if (tls_want_async_job(s))
        return tls_ERROR_WANT_ASYNC_JOB;
    if (tls_want_client_hello_cb(s))
        return tls_ERROR_WANT_CLIENT_HELLO_CB;

    if ((s->shutdown & tls_RECEIVED_SHUTDOWN) &&
        (s->s3.warn_alert == tls_AD_CLOSE_NOTIFY))
        return tls_ERROR_ZERO_RETURN;

    return tls_ERROR_SYSCALL;
}

static int tls_do_handshake_intern(void *vargs)
{
    struct tls_async_args *args;
    tls *s;

    args = (struct tls_async_args *)vargs;
    s = args->s;

    return s->handshake_func(s);
}

int tls_do_handshake(tls *s)
{
    int ret = 1;

    if (s->handshake_func == NULL) {
        tlserr(tls_F_tls_DO_HANDSHAKE, tls_R_CONNECTION_TYPE_NOT_SET);
        return -1;
    }

    otls_statem_check_finish_init(s, -1);

    s->method->tls_renegotiate_check(s, 0);

    if (tls_in_init(s) || tls_in_before(s)) {
        if ((s->mode & tls_MODE_ASYNC) && ASYNC_get_current_job() == NULL) {
            struct tls_async_args args;

            args.s = s;

            ret = tls_start_async_job(s, &args, tls_do_handshake_intern);
        } else {
            ret = s->handshake_func(s);
        }
    }
    return ret;
}

void tls_set_accept_state(tls *s)
{
    s->server = 1;
    s->shutdown = 0;
    otls_statem_clear(s);
    s->handshake_func = s->method->tls_accept;
    clear_ciphers(s);
}

void tls_set_connect_state(tls *s)
{
    s->server = 0;
    s->shutdown = 0;
    otls_statem_clear(s);
    s->handshake_func = s->method->tls_connect;
    clear_ciphers(s);
}

int tls_undefined_function(tls *s)
{
    tlserr(tls_F_tls_UNDEFINED_FUNCTION, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return 0;
}

int tls_undefined_void_function(void)
{
    tlserr(tls_F_tls_UNDEFINED_VOID_FUNCTION,
           ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return 0;
}

int tls_undefined_const_function(const tls *s)
{
    return 0;
}

const tls_METHOD *tls_bad_method(int ver)
{
    tlserr(tls_F_tls_BAD_METHOD, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return NULL;
}

const char *tls_protocol_to_string(int version)
{
    switch(version)
    {
    case TLS1_3_VERSION:
        return "TLSv1.3";

    case TLS1_2_VERSION:
        return "TLSv1.2";

    case TLS1_1_VERSION:
        return "TLSv1.1";

    case TLS1_VERSION:
        return "TLSv1";

    case tls3_VERSION:
        return "tlsv3";

    case DTLS1_BAD_VER:
        return "DTLSv0.9";

    case DTLS1_VERSION:
        return "DTLSv1";

    case DTLS1_2_VERSION:
        return "DTLSv1.2";

    default:
        return "unknown";
    }
}

const char *tls_get_version(const tls *s)
{
    return tls_protocol_to_string(s->version);
}

static int dup_ca_names(STACK_OF(X509_NAME) **dst, STACK_OF(X509_NAME) *src)
{
    STACK_OF(X509_NAME) *sk;
    X509_NAME *xn;
    int i;

    if (src == NULL) {
        *dst = NULL;
        return 1;
    }

    if ((sk = sk_X509_NAME_new_null()) == NULL)
        return 0;
    for (i = 0; i < sk_X509_NAME_num(src); i++) {
        xn = X509_NAME_dup(sk_X509_NAME_value(src, i));
        if (xn == NULL) {
            sk_X509_NAME_pop_free(sk, X509_NAME_free);
            return 0;
        }
        if (sk_X509_NAME_insert(sk, xn, i) == 0) {
            X509_NAME_free(xn);
            sk_X509_NAME_pop_free(sk, X509_NAME_free);
            return 0;
        }
    }
    *dst = sk;

    return 1;
}

tls *tls_dup(tls *s)
{
    tls *ret;
    int i;

    /* If we're not quiescent, just up_ref! */
    if (!tls_in_init(s) || !tls_in_before(s)) {
        CRYPTO_UP_REF(&s->references, &i, s->lock);
        return s;
    }

    /*
     * Otherwise, copy configuration state, and session if set.
     */
    if ((ret = tls_new(tls_get_tls_CTX(s))) == NULL)
        return NULL;

    if (s->session != NULL) {
        /*
         * Arranges to share the same session via up_ref.  This "copies"
         * session-id, tls_METHOD, sid_ctx, and 'cert'
         */
        if (!tls_copy_session_id(ret, s))
            goto err;
    } else {
        /*
         * No session has been established yet, so we have to expect that
         * s->cert or ret->cert will be changed later -- they should not both
         * point to the same object, and thus we can't use
         * tls_copy_session_id.
         */
        if (!tls_set_tls_method(ret, s->method))
            goto err;

        if (s->cert != NULL) {
            tls_cert_free(ret->cert);
            ret->cert = tls_cert_dup(s->cert);
            if (ret->cert == NULL)
                goto err;
        }

        if (!tls_set_session_id_context(ret, s->sid_ctx,
                                        (int)s->sid_ctx_length))
            goto err;
    }

    if (!tls_dane_dup(ret, s))
        goto err;
    ret->version = s->version;
    ret->options = s->options;
    ret->mode = s->mode;
    tls_set_max_cert_list(ret, tls_get_max_cert_list(s));
    tls_set_read_ahead(ret, tls_get_read_ahead(s));
    ret->msg_callback = s->msg_callback;
    ret->msg_callback_arg = s->msg_callback_arg;
    tls_set_verify(ret, tls_get_verify_mode(s), tls_get_verify_callback(s));
    tls_set_verify_depth(ret, tls_get_verify_depth(s));
    ret->generate_session_id = s->generate_session_id;

    tls_set_info_callback(ret, tls_get_info_callback(s));

    /* copy app data, a little dangerous perhaps */
    if (!CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_tls, &ret->ex_data, &s->ex_data))
        goto err;

    /* setup rbio, and wbio */
    if (s->rbio != NULL) {
        if (!BIO_dup_state(s->rbio, (char *)&ret->rbio))
            goto err;
    }
    if (s->wbio != NULL) {
        if (s->wbio != s->rbio) {
            if (!BIO_dup_state(s->wbio, (char *)&ret->wbio))
                goto err;
        } else {
            BIO_up_ref(ret->rbio);
            ret->wbio = ret->rbio;
        }
    }

    ret->server = s->server;
    if (s->handshake_func) {
        if (s->server)
            tls_set_accept_state(ret);
        else
            tls_set_connect_state(ret);
    }
    ret->shutdown = s->shutdown;
    ret->hit = s->hit;

    ret->default_passwd_callback = s->default_passwd_callback;
    ret->default_passwd_callback_userdata = s->default_passwd_callback_userdata;

    X509_VERIFY_PARAM_inherit(ret->param, s->param);

    /* dup the cipher_list and cipher_list_by_id stacks */
    if (s->cipher_list != NULL) {
        if ((ret->cipher_list = sk_tls_CIPHER_dup(s->cipher_list)) == NULL)
            goto err;
    }
    if (s->cipher_list_by_id != NULL)
        if ((ret->cipher_list_by_id = sk_tls_CIPHER_dup(s->cipher_list_by_id))
            == NULL)
            goto err;

    /* Dup the client_CA list */
    if (!dup_ca_names(&ret->ca_names, s->ca_names)
            || !dup_ca_names(&ret->client_ca_names, s->client_ca_names))
        goto err;

    return ret;

 err:
    tls_free(ret);
    return NULL;
}

void tls_clear_cipher_ctx(tls *s)
{
    if (s->enc_read_ctx != NULL) {
        EVP_CIPHER_CTX_free(s->enc_read_ctx);
        s->enc_read_ctx = NULL;
    }
    if (s->enc_write_ctx != NULL) {
        EVP_CIPHER_CTX_free(s->enc_write_ctx);
        s->enc_write_ctx = NULL;
    }
#ifndef OPENtls_NO_COMP
    COMP_CTX_free(s->expand);
    s->expand = NULL;
    COMP_CTX_free(s->compress);
    s->compress = NULL;
#endif
}

X509 *tls_get_certificate(const tls *s)
{
    if (s->cert != NULL)
        return s->cert->key->x509;
    else
        return NULL;
}

EVP_PKEY *tls_get_privatekey(const tls *s)
{
    if (s->cert != NULL)
        return s->cert->key->privatekey;
    else
        return NULL;
}

X509 *tls_CTX_get0_certificate(const tls_CTX *ctx)
{
    if (ctx->cert != NULL)
        return ctx->cert->key->x509;
    else
        return NULL;
}

EVP_PKEY *tls_CTX_get0_privatekey(const tls_CTX *ctx)
{
    if (ctx->cert != NULL)
        return ctx->cert->key->privatekey;
    else
        return NULL;
}

const tls_CIPHER *tls_get_current_cipher(const tls *s)
{
    if ((s->session != NULL) && (s->session->cipher != NULL))
        return s->session->cipher;
    return NULL;
}

const tls_CIPHER *tls_get_pending_cipher(const tls *s)
{
    return s->s3.tmp.new_cipher;
}

const COMP_METHOD *tls_get_current_compression(const tls *s)
{
#ifndef OPENtls_NO_COMP
    return s->compress ? COMP_CTX_get_method(s->compress) : NULL;
#else
    return NULL;
#endif
}

const COMP_METHOD *tls_get_current_expansion(const tls *s)
{
#ifndef OPENtls_NO_COMP
    return s->expand ? COMP_CTX_get_method(s->expand) : NULL;
#else
    return NULL;
#endif
}

int tls_init_wbio_buffer(tls *s)
{
    BIO *bbio;

    if (s->bbio != NULL) {
        /* Already buffered. */
        return 1;
    }

    bbio = BIO_new(BIO_f_buffer());
    if (bbio == NULL || !BIO_set_read_buffer_size(bbio, 1)) {
        BIO_free(bbio);
        tlserr(tls_F_tls_INIT_WBIO_BUFFER, ERR_R_BUF_LIB);
        return 0;
    }
    s->bbio = bbio;
    s->wbio = BIO_push(bbio, s->wbio);

    return 1;
}

int tls_free_wbio_buffer(tls *s)
{
    /* callers ensure s is never null */
    if (s->bbio == NULL)
        return 1;

    s->wbio = BIO_pop(s->wbio);
    BIO_free(s->bbio);
    s->bbio = NULL;

    return 1;
}

void tls_CTX_set_quiet_shutdown(tls_CTX *ctx, int mode)
{
    ctx->quiet_shutdown = mode;
}

int tls_CTX_get_quiet_shutdown(const tls_CTX *ctx)
{
    return ctx->quiet_shutdown;
}

void tls_set_quiet_shutdown(tls *s, int mode)
{
    s->quiet_shutdown = mode;
}

int tls_get_quiet_shutdown(const tls *s)
{
    return s->quiet_shutdown;
}

void tls_set_shutdown(tls *s, int mode)
{
    s->shutdown = mode;
}

int tls_get_shutdown(const tls *s)
{
    return s->shutdown;
}

int tls_version(const tls *s)
{
    return s->version;
}

int tls_client_version(const tls *s)
{
    return s->client_version;
}

tls_CTX *tls_get_tls_CTX(const tls *tls)
{
    return tls->ctx;
}

tls_CTX *tls_set_tls_CTX(tls *tls, tls_CTX *ctx)
{
    CERT *new_cert;
    if (tls->ctx == ctx)
        return tls->ctx;
    if (ctx == NULL)
        ctx = tls->session_ctx;
    new_cert = tls_cert_dup(ctx->cert);
    if (new_cert == NULL) {
        return NULL;
    }

    if (!custom_exts_copy_flags(&new_cert->custext, &tls->cert->custext)) {
        tls_cert_free(new_cert);
        return NULL;
    }

    tls_cert_free(tls->cert);
    tls->cert = new_cert;

    /*
     * Program invariant: |sid_ctx| has fixed size (tls_MAX_SID_CTX_LENGTH),
     * so setter APIs must prevent invalid lengths from entering the system.
     */
    if (!otls_assert(tls->sid_ctx_length <= sizeof(tls->sid_ctx)))
        return NULL;

    /*
     * If the session ID context matches that of the parent tls_CTX,
     * inherit it from the new tls_CTX as well. If however the context does
     * not match (i.e., it was set per-tls with tls_set_session_id_context),
     * leave it unchanged.
     */
    if ((tls->ctx != NULL) &&
        (tls->sid_ctx_length == tls->ctx->sid_ctx_length) &&
        (memcmp(tls->sid_ctx, tls->ctx->sid_ctx, tls->sid_ctx_length) == 0)) {
        tls->sid_ctx_length = ctx->sid_ctx_length;
        memcpy(&tls->sid_ctx, &ctx->sid_ctx, sizeof(tls->sid_ctx));
    }

    tls_CTX_up_ref(ctx);
    tls_CTX_free(tls->ctx);     /* decrement reference count */
    tls->ctx = ctx;

    return tls->ctx;
}

int tls_CTX_set_default_verify_paths(tls_CTX *ctx)
{
    return X509_STORE_set_default_paths(ctx->cert_store);
}

int tls_CTX_set_default_verify_dir(tls_CTX *ctx)
{
    X509_LOOKUP *lookup;

    lookup = X509_STORE_add_lookup(ctx->cert_store, X509_LOOKUP_hash_dir());
    if (lookup == NULL)
        return 0;

    /* We ignore errors, in case the directory doesn't exist */
    ERR_set_mark();

    X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);

    ERR_pop_to_mark();

    return 1;
}

int tls_CTX_set_default_verify_file(tls_CTX *ctx)
{
    X509_LOOKUP *lookup;

    lookup = X509_STORE_add_lookup(ctx->cert_store, X509_LOOKUP_file());
    if (lookup == NULL)
        return 0;

    /* We ignore errors, in case the directory doesn't exist */
    ERR_set_mark();

    X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);

    ERR_pop_to_mark();

    return 1;
}

int tls_CTX_set_default_verify_store(tls_CTX *ctx)
{
    X509_LOOKUP *lookup;

    lookup = X509_STORE_add_lookup(ctx->cert_store, X509_LOOKUP_store());
    if (lookup == NULL)
        return 0;

    /* We ignore errors, in case the directory doesn't exist */
    ERR_set_mark();

    X509_LOOKUP_add_store(lookup, NULL);

    ERR_pop_to_mark();

    return 1;
}

int tls_CTX_load_verify_file(tls_CTX *ctx, const char *CAfile)
{
    return X509_STORE_load_file(ctx->cert_store, CAfile);
}

int tls_CTX_load_verify_dir(tls_CTX *ctx, const char *CApath)
{
    return X509_STORE_load_path(ctx->cert_store, CApath);
}

int tls_CTX_load_verify_store(tls_CTX *ctx, const char *CAstore)
{
    return X509_STORE_load_store(ctx->cert_store, CAstore);
}

#ifndef OPENtls_NO_DEPRECATED_3_0
int tls_CTX_load_verify_locations(tls_CTX *ctx, const char *CAfile,
                                  const char *CApath)
{
    if (CAfile == NULL && CApath == NULL)
        return 0;
    if (CAfile != NULL && !tls_CTX_load_verify_file(ctx, CAfile))
        return 0;
    if (CApath != NULL && !tls_CTX_load_verify_dir(ctx, CApath))
        return 0;
    return 1;
}
#endif

void tls_set_info_callback(tls *tls,
                           void (*cb) (const tls *tls, int type, int val))
{
    tls->info_callback = cb;
}

/*
 * One compiler (Diab DCC) doesn't like argument names in returned function
 * pointer.
 */
void (*tls_get_info_callback(const tls *tls)) (const tls * /* tls */ ,
                                               int /* type */ ,
                                               int /* val */ ) {
    return tls->info_callback;
}

void tls_set_verify_result(tls *tls, long arg)
{
    tls->verify_result = arg;
}

long tls_get_verify_result(const tls *tls)
{
    return tls->verify_result;
}

size_t tls_get_client_random(const tls *tls, unsigned char *out, size_t outlen)
{
    if (outlen == 0)
        return sizeof(tls->s3.client_random);
    if (outlen > sizeof(tls->s3.client_random))
        outlen = sizeof(tls->s3.client_random);
    memcpy(out, tls->s3.client_random, outlen);
    return outlen;
}

size_t tls_get_server_random(const tls *tls, unsigned char *out, size_t outlen)
{
    if (outlen == 0)
        return sizeof(tls->s3.server_random);
    if (outlen > sizeof(tls->s3.server_random))
        outlen = sizeof(tls->s3.server_random);
    memcpy(out, tls->s3.server_random, outlen);
    return outlen;
}

size_t tls_SESSION_get_master_key(const tls_SESSION *session,
                                  unsigned char *out, size_t outlen)
{
    if (outlen == 0)
        return session->master_key_length;
    if (outlen > session->master_key_length)
        outlen = session->master_key_length;
    memcpy(out, session->master_key, outlen);
    return outlen;
}

int tls_SESSION_set1_master_key(tls_SESSION *sess, const unsigned char *in,
                                size_t len)
{
    if (len > sizeof(sess->master_key))
        return 0;

    memcpy(sess->master_key, in, len);
    sess->master_key_length = len;
    return 1;
}


int tls_set_ex_data(tls *s, int idx, void *arg)
{
    return CRYPTO_set_ex_data(&s->ex_data, idx, arg);
}

void *tls_get_ex_data(const tls *s, int idx)
{
    return CRYPTO_get_ex_data(&s->ex_data, idx);
}

int tls_CTX_set_ex_data(tls_CTX *s, int idx, void *arg)
{
    return CRYPTO_set_ex_data(&s->ex_data, idx, arg);
}

void *tls_CTX_get_ex_data(const tls_CTX *s, int idx)
{
    return CRYPTO_get_ex_data(&s->ex_data, idx);
}

X509_STORE *tls_CTX_get_cert_store(const tls_CTX *ctx)
{
    return ctx->cert_store;
}

void tls_CTX_set_cert_store(tls_CTX *ctx, X509_STORE *store)
{
    X509_STORE_free(ctx->cert_store);
    ctx->cert_store = store;
}

void tls_CTX_set1_cert_store(tls_CTX *ctx, X509_STORE *store)
{
    if (store != NULL)
        X509_STORE_up_ref(store);
    tls_CTX_set_cert_store(ctx, store);
}

int tls_want(const tls *s)
{
    return s->rwstate;
}

/**
 * \brief Set the callback for generating temporary DH keys.
 * \param ctx the tls context.
 * \param dh the callback
 */

#ifndef OPENtls_NO_DH
void tls_CTX_set_tmp_dh_callback(tls_CTX *ctx,
                                 DH *(*dh) (tls *tls, int is_export,
                                            int keylength))
{
    tls_CTX_callback_ctrl(ctx, tls_CTRL_SET_TMP_DH_CB, (void (*)(void))dh);
}

void tls_set_tmp_dh_callback(tls *tls, DH *(*dh) (tls *tls, int is_export,
                                                  int keylength))
{
    tls_callback_ctrl(tls, tls_CTRL_SET_TMP_DH_CB, (void (*)(void))dh);
}
#endif

#ifndef OPENtls_NO_PSK
int tls_CTX_use_psk_identity_hint(tls_CTX *ctx, const char *identity_hint)
{
    if (identity_hint != NULL && strlen(identity_hint) > PSK_MAX_IDENTITY_LEN) {
        tlserr(tls_F_tls_CTX_USE_PSK_IDENTITY_HINT, tls_R_DATA_LENGTH_TOO_LONG);
        return 0;
    }
    OPENtls_free(ctx->cert->psk_identity_hint);
    if (identity_hint != NULL) {
        ctx->cert->psk_identity_hint = OPENtls_strdup(identity_hint);
        if (ctx->cert->psk_identity_hint == NULL)
            return 0;
    } else
        ctx->cert->psk_identity_hint = NULL;
    return 1;
}

int tls_use_psk_identity_hint(tls *s, const char *identity_hint)
{
    if (s == NULL)
        return 0;

    if (identity_hint != NULL && strlen(identity_hint) > PSK_MAX_IDENTITY_LEN) {
        tlserr(tls_F_tls_USE_PSK_IDENTITY_HINT, tls_R_DATA_LENGTH_TOO_LONG);
        return 0;
    }
    OPENtls_free(s->cert->psk_identity_hint);
    if (identity_hint != NULL) {
        s->cert->psk_identity_hint = OPENtls_strdup(identity_hint);
        if (s->cert->psk_identity_hint == NULL)
            return 0;
    } else
        s->cert->psk_identity_hint = NULL;
    return 1;
}

const char *tls_get_psk_identity_hint(const tls *s)
{
    if (s == NULL || s->session == NULL)
        return NULL;
    return s->session->psk_identity_hint;
}

const char *tls_get_psk_identity(const tls *s)
{
    if (s == NULL || s->session == NULL)
        return NULL;
    return s->session->psk_identity;
}

void tls_set_psk_client_callback(tls *s, tls_psk_client_cb_func cb)
{
    s->psk_client_callback = cb;
}

void tls_CTX_set_psk_client_callback(tls_CTX *ctx, tls_psk_client_cb_func cb)
{
    ctx->psk_client_callback = cb;
}

void tls_set_psk_server_callback(tls *s, tls_psk_server_cb_func cb)
{
    s->psk_server_callback = cb;
}

void tls_CTX_set_psk_server_callback(tls_CTX *ctx, tls_psk_server_cb_func cb)
{
    ctx->psk_server_callback = cb;
}
#endif

void tls_set_psk_find_session_callback(tls *s, tls_psk_find_session_cb_func cb)
{
    s->psk_find_session_cb = cb;
}

void tls_CTX_set_psk_find_session_callback(tls_CTX *ctx,
                                           tls_psk_find_session_cb_func cb)
{
    ctx->psk_find_session_cb = cb;
}

void tls_set_psk_use_session_callback(tls *s, tls_psk_use_session_cb_func cb)
{
    s->psk_use_session_cb = cb;
}

void tls_CTX_set_psk_use_session_callback(tls_CTX *ctx,
                                           tls_psk_use_session_cb_func cb)
{
    ctx->psk_use_session_cb = cb;
}

void tls_CTX_set_msg_callback(tls_CTX *ctx,
                              void (*cb) (int write_p, int version,
                                          int content_type, const void *buf,
                                          size_t len, tls *tls, void *arg))
{
    tls_CTX_callback_ctrl(ctx, tls_CTRL_SET_MSG_CALLBACK, (void (*)(void))cb);
}

void tls_set_msg_callback(tls *tls,
                          void (*cb) (int write_p, int version,
                                      int content_type, const void *buf,
                                      size_t len, tls *tls, void *arg))
{
    tls_callback_ctrl(tls, tls_CTRL_SET_MSG_CALLBACK, (void (*)(void))cb);
}

void tls_CTX_set_not_resumable_session_callback(tls_CTX *ctx,
                                                int (*cb) (tls *tls,
                                                           int
                                                           is_forward_secure))
{
    tls_CTX_callback_ctrl(ctx, tls_CTRL_SET_NOT_RESUMABLE_SESS_CB,
                          (void (*)(void))cb);
}

void tls_set_not_resumable_session_callback(tls *tls,
                                            int (*cb) (tls *tls,
                                                       int is_forward_secure))
{
    tls_callback_ctrl(tls, tls_CTRL_SET_NOT_RESUMABLE_SESS_CB,
                      (void (*)(void))cb);
}

void tls_CTX_set_record_padding_callback(tls_CTX *ctx,
                                         size_t (*cb) (tls *tls, int type,
                                                       size_t len, void *arg))
{
    ctx->record_padding_cb = cb;
}

void tls_CTX_set_record_padding_callback_arg(tls_CTX *ctx, void *arg)
{
    ctx->record_padding_arg = arg;
}

void *tls_CTX_get_record_padding_callback_arg(const tls_CTX *ctx)
{
    return ctx->record_padding_arg;
}

int tls_CTX_set_block_padding(tls_CTX *ctx, size_t block_size)
{
    /* block size of 0 or 1 is basically no padding */
    if (block_size == 1)
        ctx->block_padding = 0;
    else if (block_size <= tls3_RT_MAX_PLAIN_LENGTH)
        ctx->block_padding = block_size;
    else
        return 0;
    return 1;
}

void tls_set_record_padding_callback(tls *tls,
                                     size_t (*cb) (tls *tls, int type,
                                                   size_t len, void *arg))
{
    tls->record_padding_cb = cb;
}

void tls_set_record_padding_callback_arg(tls *tls, void *arg)
{
    tls->record_padding_arg = arg;
}

void *tls_get_record_padding_callback_arg(const tls *tls)
{
    return tls->record_padding_arg;
}

int tls_set_block_padding(tls *tls, size_t block_size)
{
    /* block size of 0 or 1 is basically no padding */
    if (block_size == 1)
        tls->block_padding = 0;
    else if (block_size <= tls3_RT_MAX_PLAIN_LENGTH)
        tls->block_padding = block_size;
    else
        return 0;
    return 1;
}

int tls_set_num_tickets(tls *s, size_t num_tickets)
{
    s->num_tickets = num_tickets;

    return 1;
}

size_t tls_get_num_tickets(const tls *s)
{
    return s->num_tickets;
}

int tls_CTX_set_num_tickets(tls_CTX *ctx, size_t num_tickets)
{
    ctx->num_tickets = num_tickets;

    return 1;
}

size_t tls_CTX_get_num_tickets(const tls_CTX *ctx)
{
    return ctx->num_tickets;
}

/*
 * Allocates new EVP_MD_CTX and sets pointer to it into given pointer
 * variable, freeing EVP_MD_CTX previously stored in that variable, if any.
 * If EVP_MD pointer is passed, initializes ctx with this |md|.
 * Returns the newly allocated ctx;
 */

EVP_MD_CTX *tls_replace_hash(EVP_MD_CTX **hash, const EVP_MD *md)
{
    tls_clear_hash_ctx(hash);
    *hash = EVP_MD_CTX_new();
    if (*hash == NULL || (md && EVP_DigestInit_ex(*hash, md, NULL) <= 0)) {
        EVP_MD_CTX_free(*hash);
        *hash = NULL;
        return NULL;
    }
    return *hash;
}

void tls_clear_hash_ctx(EVP_MD_CTX **hash)
{

    EVP_MD_CTX_free(*hash);
    *hash = NULL;
}

/* Retrieve handshake hashes */
int tls_handshake_hash(tls *s, unsigned char *out, size_t outlen,
                       size_t *hashlen)
{
    EVP_MD_CTX *ctx = NULL;
    EVP_MD_CTX *hdgst = s->s3.handshake_dgst;
    int hashleni = EVP_MD_CTX_size(hdgst);
    int ret = 0;

    if (hashleni < 0 || (size_t)hashleni > outlen) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_HANDSHAKE_HASH,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        goto err;

    if (!EVP_MD_CTX_copy_ex(ctx, hdgst)
        || EVP_DigestFinal_ex(ctx, out, NULL) <= 0) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_HANDSHAKE_HASH,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    *hashlen = hashleni;

    ret = 1;
 err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

int tls_session_reused(const tls *s)
{
    return s->hit;
}

int tls_is_server(const tls *s)
{
    return s->server;
}

#ifndef OPENtls_NO_DEPRECATED_1_1_0
void tls_set_debug(tls *s, int debug)
{
    /* Old function was do-nothing anyway... */
    (void)s;
    (void)debug;
}
#endif

void tls_set_security_level(tls *s, int level)
{
    s->cert->sec_level = level;
}

int tls_get_security_level(const tls *s)
{
    return s->cert->sec_level;
}

void tls_set_security_callback(tls *s,
                               int (*cb) (const tls *s, const tls_CTX *ctx,
                                          int op, int bits, int nid,
                                          void *other, void *ex))
{
    s->cert->sec_cb = cb;
}

int (*tls_get_security_callback(const tls *s)) (const tls *s,
                                                const tls_CTX *ctx, int op,
                                                int bits, int nid, void *other,
                                                void *ex) {
    return s->cert->sec_cb;
}

void tls_set0_security_ex_data(tls *s, void *ex)
{
    s->cert->sec_ex = ex;
}

void *tls_get0_security_ex_data(const tls *s)
{
    return s->cert->sec_ex;
}

void tls_CTX_set_security_level(tls_CTX *ctx, int level)
{
    ctx->cert->sec_level = level;
}

int tls_CTX_get_security_level(const tls_CTX *ctx)
{
    return ctx->cert->sec_level;
}

void tls_CTX_set_security_callback(tls_CTX *ctx,
                                   int (*cb) (const tls *s, const tls_CTX *ctx,
                                              int op, int bits, int nid,
                                              void *other, void *ex))
{
    ctx->cert->sec_cb = cb;
}

int (*tls_CTX_get_security_callback(const tls_CTX *ctx)) (const tls *s,
                                                          const tls_CTX *ctx,
                                                          int op, int bits,
                                                          int nid,
                                                          void *other,
                                                          void *ex) {
    return ctx->cert->sec_cb;
}

void tls_CTX_set0_security_ex_data(tls_CTX *ctx, void *ex)
{
    ctx->cert->sec_ex = ex;
}

void *tls_CTX_get0_security_ex_data(const tls_CTX *ctx)
{
    return ctx->cert->sec_ex;
}

/*
 * Get/Set/Clear options in tls_CTX or tls, formerly macros, now functions that
 * can return unsigned long, instead of the generic long return value from the
 * control interface.
 */
unsigned long tls_CTX_get_options(const tls_CTX *ctx)
{
    return ctx->options;
}

unsigned long tls_get_options(const tls *s)
{
    return s->options;
}

unsigned long tls_CTX_set_options(tls_CTX *ctx, unsigned long op)
{
    return ctx->options |= op;
}

unsigned long tls_set_options(tls *s, unsigned long op)
{
    return s->options |= op;
}

unsigned long tls_CTX_clear_options(tls_CTX *ctx, unsigned long op)
{
    return ctx->options &= ~op;
}

unsigned long tls_clear_options(tls *s, unsigned long op)
{
    return s->options &= ~op;
}

STACK_OF(X509) *tls_get0_verified_chain(const tls *s)
{
    return s->verified_chain;
}

IMPLEMENT_OBJ_BSEARCH_GLOBAL_CMP_FN(tls_CIPHER, tls_CIPHER, tls_cipher_id);

#ifndef OPENtls_NO_CT

/*
 * Moves SCTs from the |src| stack to the |dst| stack.
 * The source of each SCT will be set to |origin|.
 * If |dst| points to a NULL pointer, a new stack will be created and owned by
 * the caller.
 * Returns the number of SCTs moved, or a negative integer if an error occurs.
 */
static int ct_move_scts(STACK_OF(SCT) **dst, STACK_OF(SCT) *src,
                        sct_source_t origin)
{
    int scts_moved = 0;
    SCT *sct = NULL;

    if (*dst == NULL) {
        *dst = sk_SCT_new_null();
        if (*dst == NULL) {
            tlserr(tls_F_CT_MOVE_SCTS, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }

    while ((sct = sk_SCT_pop(src)) != NULL) {
        if (SCT_set_source(sct, origin) != 1)
            goto err;

        if (sk_SCT_push(*dst, sct) <= 0)
            goto err;
        scts_moved += 1;
    }

    return scts_moved;
 err:
    if (sct != NULL)
        sk_SCT_push(src, sct);  /* Put the SCT back */
    return -1;
}

/*
 * Look for data collected during ServerHello and parse if found.
 * Returns the number of SCTs extracted.
 */
static int ct_extract_tls_extension_scts(tls *s)
{
    int scts_extracted = 0;

    if (s->ext.scts != NULL) {
        const unsigned char *p = s->ext.scts;
        STACK_OF(SCT) *scts = o2i_SCT_LIST(NULL, &p, s->ext.scts_len);

        scts_extracted = ct_move_scts(&s->scts, scts, SCT_SOURCE_TLS_EXTENSION);

        SCT_LIST_free(scts);
    }

    return scts_extracted;
}

/*
 * Checks for an OCSP response and then attempts to extract any SCTs found if it
 * contains an SCT X509 extension. They will be stored in |s->scts|.
 * Returns:
 * - The number of SCTs extracted, assuming an OCSP response exists.
 * - 0 if no OCSP response exists or it contains no SCTs.
 * - A negative integer if an error occurs.
 */
static int ct_extract_ocsp_response_scts(tls *s)
{
# ifndef OPENtls_NO_OCSP
    int scts_extracted = 0;
    const unsigned char *p;
    OCSP_BASICRESP *br = NULL;
    OCSP_RESPONSE *rsp = NULL;
    STACK_OF(SCT) *scts = NULL;
    int i;

    if (s->ext.ocsp.resp == NULL || s->ext.ocsp.resp_len == 0)
        goto err;

    p = s->ext.ocsp.resp;
    rsp = d2i_OCSP_RESPONSE(NULL, &p, (int)s->ext.ocsp.resp_len);
    if (rsp == NULL)
        goto err;

    br = OCSP_response_get1_basic(rsp);
    if (br == NULL)
        goto err;

    for (i = 0; i < OCSP_resp_count(br); ++i) {
        OCSP_SINGLERESP *single = OCSP_resp_get0(br, i);

        if (single == NULL)
            continue;

        scts =
            OCSP_SINGLERESP_get1_ext_d2i(single, NID_ct_cert_scts, NULL, NULL);
        scts_extracted =
            ct_move_scts(&s->scts, scts, SCT_SOURCE_OCSP_STAPLED_RESPONSE);
        if (scts_extracted < 0)
            goto err;
    }
 err:
    SCT_LIST_free(scts);
    OCSP_BASICRESP_free(br);
    OCSP_RESPONSE_free(rsp);
    return scts_extracted;
# else
    /* Behave as if no OCSP response exists */
    return 0;
# endif
}

/*
 * Attempts to extract SCTs from the peer certificate.
 * Return the number of SCTs extracted, or a negative integer if an error
 * occurs.
 */
static int ct_extract_x509v3_extension_scts(tls *s)
{
    int scts_extracted = 0;
    X509 *cert = s->session != NULL ? s->session->peer : NULL;

    if (cert != NULL) {
        STACK_OF(SCT) *scts =
            X509_get_ext_d2i(cert, NID_ct_precert_scts, NULL, NULL);

        scts_extracted =
            ct_move_scts(&s->scts, scts, SCT_SOURCE_X509V3_EXTENSION);

        SCT_LIST_free(scts);
    }

    return scts_extracted;
}

/*
 * Attempts to find all received SCTs by checking TLS extensions, the OCSP
 * response (if it exists) and X509v3 extensions in the certificate.
 * Returns NULL if an error occurs.
 */
const STACK_OF(SCT) *tls_get0_peer_scts(tls *s)
{
    if (!s->scts_parsed) {
        if (ct_extract_tls_extension_scts(s) < 0 ||
            ct_extract_ocsp_response_scts(s) < 0 ||
            ct_extract_x509v3_extension_scts(s) < 0)
            goto err;

        s->scts_parsed = 1;
    }
    return s->scts;
 err:
    return NULL;
}

static int ct_permissive(const CT_POLICY_EVAL_CTX * ctx,
                         const STACK_OF(SCT) *scts, void *unused_arg)
{
    return 1;
}

static int ct_strict(const CT_POLICY_EVAL_CTX * ctx,
                     const STACK_OF(SCT) *scts, void *unused_arg)
{
    int count = scts != NULL ? sk_SCT_num(scts) : 0;
    int i;

    for (i = 0; i < count; ++i) {
        SCT *sct = sk_SCT_value(scts, i);
        int status = SCT_get_validation_status(sct);

        if (status == SCT_VALIDATION_STATUS_VALID)
            return 1;
    }
    tlserr(tls_F_CT_STRICT, tls_R_NO_VALID_SCTS);
    return 0;
}

int tls_set_ct_validation_callback(tls *s, tls_ct_validation_cb callback,
                                   void *arg)
{
    /*
     * Since code exists that uses the custom extension handler for CT, look
     * for this and throw an error if they have already registered to use CT.
     */
    if (callback != NULL && tls_CTX_has_client_custom_ext(s->ctx,
                                                          TLSEXT_TYPE_signed_certificate_timestamp))
    {
        tlserr(tls_F_tls_SET_CT_VALIDATION_CALLBACK,
               tls_R_CUSTOM_EXT_HANDLER_ALREADY_INSTALLED);
        return 0;
    }

    if (callback != NULL) {
        /*
         * If we are validating CT, then we MUST accept SCTs served via OCSP
         */
        if (!tls_set_tlsext_status_type(s, TLSEXT_STATUSTYPE_ocsp))
            return 0;
    }

    s->ct_validation_callback = callback;
    s->ct_validation_callback_arg = arg;

    return 1;
}

int tls_CTX_set_ct_validation_callback(tls_CTX *ctx,
                                       tls_ct_validation_cb callback, void *arg)
{
    /*
     * Since code exists that uses the custom extension handler for CT, look for
     * this and throw an error if they have already registered to use CT.
     */
    if (callback != NULL && tls_CTX_has_client_custom_ext(ctx,
                                                          TLSEXT_TYPE_signed_certificate_timestamp))
    {
        tlserr(tls_F_tls_CTX_SET_CT_VALIDATION_CALLBACK,
               tls_R_CUSTOM_EXT_HANDLER_ALREADY_INSTALLED);
        return 0;
    }

    ctx->ct_validation_callback = callback;
    ctx->ct_validation_callback_arg = arg;
    return 1;
}

int tls_ct_is_enabled(const tls *s)
{
    return s->ct_validation_callback != NULL;
}

int tls_CTX_ct_is_enabled(const tls_CTX *ctx)
{
    return ctx->ct_validation_callback != NULL;
}

int tls_validate_ct(tls *s)
{
    int ret = 0;
    X509 *cert = s->session != NULL ? s->session->peer : NULL;
    X509 *issuer;
    tls_DANE *dane = &s->dane;
    CT_POLICY_EVAL_CTX *ctx = NULL;
    const STACK_OF(SCT) *scts;

    /*
     * If no callback is set, the peer is anonymous, or its chain is invalid,
     * skip SCT validation - just return success.  Applications that continue
     * handshakes without certificates, with unverified chains, or pinned leaf
     * certificates are outside the scope of the WebPKI and CT.
     *
     * The above exclusions notwithstanding the vast majority of peers will
     * have rather ordinary certificate chains validated by typical
     * applications that perform certificate verification and therefore will
     * process SCTs when enabled.
     */
    if (s->ct_validation_callback == NULL || cert == NULL ||
        s->verify_result != X509_V_OK ||
        s->verified_chain == NULL || sk_X509_num(s->verified_chain) <= 1)
        return 1;

    /*
     * CT not applicable for chains validated via DANE-TA(2) or DANE-EE(3)
     * trust-anchors.  See https://tools.ietf.org/html/rfc7671#section-4.2
     */
    if (DANETLS_ENABLED(dane) && dane->mtlsa != NULL) {
        switch (dane->mtlsa->usage) {
        case DANETLS_USAGE_DANE_TA:
        case DANETLS_USAGE_DANE_EE:
            return 1;
        }
    }

    ctx = CT_POLICY_EVAL_CTX_new();
    if (ctx == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_VALIDATE_CT,
                 ERR_R_MALLOC_FAILURE);
        goto end;
    }

    issuer = sk_X509_value(s->verified_chain, 1);
    CT_POLICY_EVAL_CTX_set1_cert(ctx, cert);
    CT_POLICY_EVAL_CTX_set1_issuer(ctx, issuer);
    CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE(ctx, s->ctx->ctlog_store);
    CT_POLICY_EVAL_CTX_set_time(
            ctx, (uint64_t)tls_SESSION_get_time(tls_get0_session(s)) * 1000);

    scts = tls_get0_peer_scts(s);

    /*
     * This function returns success (> 0) only when all the SCTs are valid, 0
     * when some are invalid, and < 0 on various internal errors (out of
     * memory, etc.).  Having some, or even all, invalid SCTs is not sufficient
     * reason to abort the handshake, that decision is up to the callback.
     * Therefore, we error out only in the unexpected case that the return
     * value is negative.
     *
     * XXX: One might well argue that the return value of this function is an
     * unfortunate design choice.  Its job is only to determine the validation
     * status of each of the provided SCTs.  So long as it correctly separates
     * the wheat from the chaff it should return success.  Failure in this case
     * ought to correspond to an inability to carry out its duties.
     */
    if (SCT_LIST_validate(scts, ctx) < 0) {
        tlsfatal(s, tls_AD_HANDSHAKE_FAILURE, tls_F_tls_VALIDATE_CT,
                 tls_R_SCT_VERIFICATION_FAILED);
        goto end;
    }

    ret = s->ct_validation_callback(ctx, scts, s->ct_validation_callback_arg);
    if (ret < 0)
        ret = 0;                /* This function returns 0 on failure */
    if (!ret)
        tlsfatal(s, tls_AD_HANDSHAKE_FAILURE, tls_F_tls_VALIDATE_CT,
                 tls_R_CALLBACK_FAILED);

 end:
    CT_POLICY_EVAL_CTX_free(ctx);
    /*
     * With tls_VERIFY_NONE the session may be cached and re-used despite a
     * failure return code here.  Also the application may wish the complete
     * the handshake, and then disconnect cleanly at a higher layer, after
     * checking the verification status of the completed connection.
     *
     * We therefore force a certificate verification failure which will be
     * visible via tls_get_verify_result() and cached as part of any resumed
     * session.
     *
     * Note: the permissive callback is for information gathering only, always
     * returns success, and does not affect verification status.  Only the
     * strict callback or a custom application-specified callback can trigger
     * connection failure or record a verification error.
     */
    if (ret <= 0)
        s->verify_result = X509_V_ERR_NO_VALID_SCTS;
    return ret;
}

int tls_CTX_enable_ct(tls_CTX *ctx, int validation_mode)
{
    switch (validation_mode) {
    default:
        tlserr(tls_F_tls_CTX_ENABLE_CT, tls_R_INVALID_CT_VALIDATION_TYPE);
        return 0;
    case tls_CT_VALIDATION_PERMISSIVE:
        return tls_CTX_set_ct_validation_callback(ctx, ct_permissive, NULL);
    case tls_CT_VALIDATION_STRICT:
        return tls_CTX_set_ct_validation_callback(ctx, ct_strict, NULL);
    }
}

int tls_enable_ct(tls *s, int validation_mode)
{
    switch (validation_mode) {
    default:
        tlserr(tls_F_tls_ENABLE_CT, tls_R_INVALID_CT_VALIDATION_TYPE);
        return 0;
    case tls_CT_VALIDATION_PERMISSIVE:
        return tls_set_ct_validation_callback(s, ct_permissive, NULL);
    case tls_CT_VALIDATION_STRICT:
        return tls_set_ct_validation_callback(s, ct_strict, NULL);
    }
}

int tls_CTX_set_default_ctlog_list_file(tls_CTX *ctx)
{
    return CTLOG_STORE_load_default_file(ctx->ctlog_store);
}

int tls_CTX_set_ctlog_list_file(tls_CTX *ctx, const char *path)
{
    return CTLOG_STORE_load_file(ctx->ctlog_store, path);
}

void tls_CTX_set0_ctlog_store(tls_CTX *ctx, CTLOG_STORE * logs)
{
    CTLOG_STORE_free(ctx->ctlog_store);
    ctx->ctlog_store = logs;
}

const CTLOG_STORE *tls_CTX_get0_ctlog_store(const tls_CTX *ctx)
{
    return ctx->ctlog_store;
}

#endif  /* OPENtls_NO_CT */

void tls_CTX_set_client_hello_cb(tls_CTX *c, tls_client_hello_cb_fn cb,
                                 void *arg)
{
    c->client_hello_cb = cb;
    c->client_hello_cb_arg = arg;
}

int tls_client_hello_isv2(tls *s)
{
    if (s->clienthello == NULL)
        return 0;
    return s->clienthello->isv2;
}

unsigned int tls_client_hello_get0_legacy_version(tls *s)
{
    if (s->clienthello == NULL)
        return 0;
    return s->clienthello->legacy_version;
}

size_t tls_client_hello_get0_random(tls *s, const unsigned char **out)
{
    if (s->clienthello == NULL)
        return 0;
    if (out != NULL)
        *out = s->clienthello->random;
    return tls3_RANDOM_SIZE;
}

size_t tls_client_hello_get0_session_id(tls *s, const unsigned char **out)
{
    if (s->clienthello == NULL)
        return 0;
    if (out != NULL)
        *out = s->clienthello->session_id;
    return s->clienthello->session_id_len;
}

size_t tls_client_hello_get0_ciphers(tls *s, const unsigned char **out)
{
    if (s->clienthello == NULL)
        return 0;
    if (out != NULL)
        *out = PACKET_data(&s->clienthello->ciphersuites);
    return PACKET_remaining(&s->clienthello->ciphersuites);
}

size_t tls_client_hello_get0_compression_methods(tls *s, const unsigned char **out)
{
    if (s->clienthello == NULL)
        return 0;
    if (out != NULL)
        *out = s->clienthello->compressions;
    return s->clienthello->compressions_len;
}

int tls_client_hello_get1_extensions_present(tls *s, int **out, size_t *outlen)
{
    RAW_EXTENSION *ext;
    int *present;
    size_t num = 0, i;

    if (s->clienthello == NULL || out == NULL || outlen == NULL)
        return 0;
    for (i = 0; i < s->clienthello->pre_proc_exts_len; i++) {
        ext = s->clienthello->pre_proc_exts + i;
        if (ext->present)
            num++;
    }
    if (num == 0) {
        *out = NULL;
        *outlen = 0;
        return 1;
    }
    if ((present = OPENtls_malloc(sizeof(*present) * num)) == NULL) {
        tlserr(tls_F_tls_CLIENT_HELLO_GET1_EXTENSIONS_PRESENT,
               ERR_R_MALLOC_FAILURE);
        return 0;
    }
    for (i = 0; i < s->clienthello->pre_proc_exts_len; i++) {
        ext = s->clienthello->pre_proc_exts + i;
        if (ext->present) {
            if (ext->received_order >= num)
                goto err;
            present[ext->received_order] = ext->type;
        }
    }
    *out = present;
    *outlen = num;
    return 1;
 err:
    OPENtls_free(present);
    return 0;
}

int tls_client_hello_get0_ext(tls *s, unsigned int type, const unsigned char **out,
                       size_t *outlen)
{
    size_t i;
    RAW_EXTENSION *r;

    if (s->clienthello == NULL)
        return 0;
    for (i = 0; i < s->clienthello->pre_proc_exts_len; ++i) {
        r = s->clienthello->pre_proc_exts + i;
        if (r->present && r->type == type) {
            if (out != NULL)
                *out = PACKET_data(&r->data);
            if (outlen != NULL)
                *outlen = PACKET_remaining(&r->data);
            return 1;
        }
    }
    return 0;
}

int tls_free_buffers(tls *tls)
{
    RECORD_LAYER *rl = &tls->rlayer;

    if (RECORD_LAYER_read_pending(rl) || RECORD_LAYER_write_pending(rl))
        return 0;

    RECORD_LAYER_release(rl);
    return 1;
}

int tls_alloc_buffers(tls *tls)
{
    return tls3_setup_buffers(tls);
}

void tls_CTX_set_keylog_callback(tls_CTX *ctx, tls_CTX_keylog_cb_func cb)
{
    ctx->keylog_callback = cb;
}

tls_CTX_keylog_cb_func tls_CTX_get_keylog_callback(const tls_CTX *ctx)
{
    return ctx->keylog_callback;
}

static int nss_keylog_int(const char *prefix,
                          tls *tls,
                          const uint8_t *parameter_1,
                          size_t parameter_1_len,
                          const uint8_t *parameter_2,
                          size_t parameter_2_len)
{
    char *out = NULL;
    char *cursor = NULL;
    size_t out_len = 0;
    size_t i;
    size_t prefix_len;

    if (tls->ctx->keylog_callback == NULL)
        return 1;

    /*
     * Our output buffer will contain the following strings, rendered with
     * space characters in between, terminated by a NULL character: first the
     * prefix, then the first parameter, then the second parameter. The
     * meaning of each parameter depends on the specific key material being
     * logged. Note that the first and second parameters are encoded in
     * hexadecimal, so we need a buffer that is twice their lengths.
     */
    prefix_len = strlen(prefix);
    out_len = prefix_len + (2 * parameter_1_len) + (2 * parameter_2_len) + 3;
    if ((out = cursor = OPENtls_malloc(out_len)) == NULL) {
        tlsfatal(tls, tls_AD_INTERNAL_ERROR, tls_F_NSS_KEYLOG_INT,
                 ERR_R_MALLOC_FAILURE);
        return 0;
    }

    strcpy(cursor, prefix);
    cursor += prefix_len;
    *cursor++ = ' ';

    for (i = 0; i < parameter_1_len; i++) {
        sprintf(cursor, "%02x", parameter_1[i]);
        cursor += 2;
    }
    *cursor++ = ' ';

    for (i = 0; i < parameter_2_len; i++) {
        sprintf(cursor, "%02x", parameter_2[i]);
        cursor += 2;
    }
    *cursor = '\0';

    tls->ctx->keylog_callback(tls, (const char *)out);
    OPENtls_clear_free(out, out_len);
    return 1;

}

int tls_log_rsa_client_key_exchange(tls *tls,
                                    const uint8_t *encrypted_premaster,
                                    size_t encrypted_premaster_len,
                                    const uint8_t *premaster,
                                    size_t premaster_len)
{
    if (encrypted_premaster_len < 8) {
        tlsfatal(tls, tls_AD_INTERNAL_ERROR,
                 tls_F_tls_LOG_RSA_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* We only want the first 8 bytes of the encrypted premaster as a tag. */
    return nss_keylog_int("RSA",
                          tls,
                          encrypted_premaster,
                          8,
                          premaster,
                          premaster_len);
}

int tls_log_secret(tls *tls,
                   const char *label,
                   const uint8_t *secret,
                   size_t secret_len)
{
    return nss_keylog_int(label,
                          tls,
                          tls->s3.client_random,
                          tls3_RANDOM_SIZE,
                          secret,
                          secret_len);
}

#define tlsV2_CIPHER_LEN    3

int tls_cache_cipherlist(tls *s, PACKET *cipher_suites, int tlsv2format)
{
    int n;

    n = tlsv2format ? tlsV2_CIPHER_LEN : TLS_CIPHER_LEN;

    if (PACKET_remaining(cipher_suites) == 0) {
        tlsfatal(s, tls_AD_ILLEGAL_PARAMETER, tls_F_tls_CACHE_CIPHERLIST,
                 tls_R_NO_CIPHERS_SPECIFIED);
        return 0;
    }

    if (PACKET_remaining(cipher_suites) % n != 0) {
        tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_tls_CACHE_CIPHERLIST,
                 tls_R_ERROR_IN_RECEIVED_CIPHER_LIST);
        return 0;
    }

    OPENtls_free(s->s3.tmp.ciphers_raw);
    s->s3.tmp.ciphers_raw = NULL;
    s->s3.tmp.ciphers_rawlen = 0;

    if (tlsv2format) {
        size_t numciphers = PACKET_remaining(cipher_suites) / n;
        PACKET tlsv2ciphers = *cipher_suites;
        unsigned int leadbyte;
        unsigned char *raw;

        /*
         * We store the raw ciphers list in tlsv3+ format so we need to do some
         * preprocessing to convert the list first. If there are any tlsv2 only
         * ciphersuites with a non-zero leading byte then we are going to
         * slightly over allocate because we won't store those. But that isn't a
         * problem.
         */
        raw = OPENtls_malloc(numciphers * TLS_CIPHER_LEN);
        s->s3.tmp.ciphers_raw = raw;
        if (raw == NULL) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_CACHE_CIPHERLIST,
                     ERR_R_MALLOC_FAILURE);
            return 0;
        }
        for (s->s3.tmp.ciphers_rawlen = 0;
             PACKET_remaining(&tlsv2ciphers) > 0;
             raw += TLS_CIPHER_LEN) {
            if (!PACKET_get_1(&tlsv2ciphers, &leadbyte)
                    || (leadbyte == 0
                        && !PACKET_copy_bytes(&tlsv2ciphers, raw,
                                              TLS_CIPHER_LEN))
                    || (leadbyte != 0
                        && !PACKET_forward(&tlsv2ciphers, TLS_CIPHER_LEN))) {
                tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_tls_CACHE_CIPHERLIST,
                         tls_R_BAD_PACKET);
                OPENtls_free(s->s3.tmp.ciphers_raw);
                s->s3.tmp.ciphers_raw = NULL;
                s->s3.tmp.ciphers_rawlen = 0;
                return 0;
            }
            if (leadbyte == 0)
                s->s3.tmp.ciphers_rawlen += TLS_CIPHER_LEN;
        }
    } else if (!PACKET_memdup(cipher_suites, &s->s3.tmp.ciphers_raw,
                           &s->s3.tmp.ciphers_rawlen)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_CACHE_CIPHERLIST,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    return 1;
}

int tls_bytes_to_cipher_list(tls *s, const unsigned char *bytes, size_t len,
                             int isv2format, STACK_OF(tls_CIPHER) **sk,
                             STACK_OF(tls_CIPHER) **scsvs)
{
    PACKET pkt;

    if (!PACKET_buf_init(&pkt, bytes, len))
        return 0;
    return bytes_to_cipher_list(s, &pkt, sk, scsvs, isv2format, 0);
}

int bytes_to_cipher_list(tls *s, PACKET *cipher_suites,
                         STACK_OF(tls_CIPHER) **skp,
                         STACK_OF(tls_CIPHER) **scsvs_out,
                         int tlsv2format, int fatal)
{
    const tls_CIPHER *c;
    STACK_OF(tls_CIPHER) *sk = NULL;
    STACK_OF(tls_CIPHER) *scsvs = NULL;
    int n;
    /* 3 = tlsV2_CIPHER_LEN > TLS_CIPHER_LEN = 2. */
    unsigned char cipher[tlsV2_CIPHER_LEN];

    n = tlsv2format ? tlsV2_CIPHER_LEN : TLS_CIPHER_LEN;

    if (PACKET_remaining(cipher_suites) == 0) {
        if (fatal)
            tlsfatal(s, tls_AD_ILLEGAL_PARAMETER, tls_F_BYTES_TO_CIPHER_LIST,
                     tls_R_NO_CIPHERS_SPECIFIED);
        else
            tlserr(tls_F_BYTES_TO_CIPHER_LIST, tls_R_NO_CIPHERS_SPECIFIED);
        return 0;
    }

    if (PACKET_remaining(cipher_suites) % n != 0) {
        if (fatal)
            tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_BYTES_TO_CIPHER_LIST,
                     tls_R_ERROR_IN_RECEIVED_CIPHER_LIST);
        else
            tlserr(tls_F_BYTES_TO_CIPHER_LIST,
                   tls_R_ERROR_IN_RECEIVED_CIPHER_LIST);
        return 0;
    }

    sk = sk_tls_CIPHER_new_null();
    scsvs = sk_tls_CIPHER_new_null();
    if (sk == NULL || scsvs == NULL) {
        if (fatal)
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_BYTES_TO_CIPHER_LIST,
                     ERR_R_MALLOC_FAILURE);
        else
            tlserr(tls_F_BYTES_TO_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    while (PACKET_copy_bytes(cipher_suites, cipher, n)) {
        /*
         * tlsv3 ciphers wrapped in an tlsv2-compatible ClientHello have the
         * first byte set to zero, while true tlsv2 ciphers have a non-zero
         * first byte. We don't support any true tlsv2 ciphers, so skip them.
         */
        if (tlsv2format && cipher[0] != '\0')
            continue;

        /* For tlsv2-compat, ignore leading 0-byte. */
        c = tls_get_cipher_by_char(s, tlsv2format ? &cipher[1] : cipher, 1);
        if (c != NULL) {
            if ((c->valid && !sk_tls_CIPHER_push(sk, c)) ||
                (!c->valid && !sk_tls_CIPHER_push(scsvs, c))) {
                if (fatal)
                    tlsfatal(s, tls_AD_INTERNAL_ERROR,
                             tls_F_BYTES_TO_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
                else
                    tlserr(tls_F_BYTES_TO_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
    }
    if (PACKET_remaining(cipher_suites) > 0) {
        if (fatal)
            tlsfatal(s, tls_AD_DECODE_ERROR, tls_F_BYTES_TO_CIPHER_LIST,
                     tls_R_BAD_LENGTH);
        else
            tlserr(tls_F_BYTES_TO_CIPHER_LIST, tls_R_BAD_LENGTH);
        goto err;
    }

    if (skp != NULL)
        *skp = sk;
    else
        sk_tls_CIPHER_free(sk);
    if (scsvs_out != NULL)
        *scsvs_out = scsvs;
    else
        sk_tls_CIPHER_free(scsvs);
    return 1;
 err:
    sk_tls_CIPHER_free(sk);
    sk_tls_CIPHER_free(scsvs);
    return 0;
}

int tls_CTX_set_max_early_data(tls_CTX *ctx, uint32_t max_early_data)
{
    ctx->max_early_data = max_early_data;

    return 1;
}

uint32_t tls_CTX_get_max_early_data(const tls_CTX *ctx)
{
    return ctx->max_early_data;
}

int tls_set_max_early_data(tls *s, uint32_t max_early_data)
{
    s->max_early_data = max_early_data;

    return 1;
}

uint32_t tls_get_max_early_data(const tls *s)
{
    return s->max_early_data;
}

int tls_CTX_set_recv_max_early_data(tls_CTX *ctx, uint32_t recv_max_early_data)
{
    ctx->recv_max_early_data = recv_max_early_data;

    return 1;
}

uint32_t tls_CTX_get_recv_max_early_data(const tls_CTX *ctx)
{
    return ctx->recv_max_early_data;
}

int tls_set_recv_max_early_data(tls *s, uint32_t recv_max_early_data)
{
    s->recv_max_early_data = recv_max_early_data;

    return 1;
}

uint32_t tls_get_recv_max_early_data(const tls *s)
{
    return s->recv_max_early_data;
}

__owur unsigned int tls_get_max_send_fragment(const tls *tls)
{
    /* Return any active Max Fragment Len extension */
    if (tls->session != NULL && USE_MAX_FRAGMENT_LENGTH_EXT(tls->session))
        return GET_MAX_FRAGMENT_LENGTH(tls->session);

    /* return current tls connection setting */
    return tls->max_send_fragment;
}

__owur unsigned int tls_get_split_send_fragment(const tls *tls)
{
    /* Return a value regarding an active Max Fragment Len extension */
    if (tls->session != NULL && USE_MAX_FRAGMENT_LENGTH_EXT(tls->session)
        && tls->split_send_fragment > GET_MAX_FRAGMENT_LENGTH(tls->session))
        return GET_MAX_FRAGMENT_LENGTH(tls->session);

    /* else limit |split_send_fragment| to current |max_send_fragment| */
    if (tls->split_send_fragment > tls->max_send_fragment)
        return tls->max_send_fragment;

    /* return current tls connection setting */
    return tls->split_send_fragment;
}

int tls_stateless(tls *s)
{
    int ret;

    /* Ensure there is no state left over from a previous invocation */
    if (!tls_clear(s))
        return 0;

    ERR_clear_error();

    s->s3.flags |= TLS1_FLAGS_STATELESS;
    ret = tls_accept(s);
    s->s3.flags &= ~TLS1_FLAGS_STATELESS;

    if (ret > 0 && s->ext.cookieok)
        return 1;

    if (s->hello_retry_request == tls_HRR_PENDING && !otls_statem_in_error(s))
        return 0;

    return -1;
}

void tls_CTX_set_post_handshake_auth(tls_CTX *ctx, int val)
{
    ctx->pha_enabled = val;
}

void tls_set_post_handshake_auth(tls *tls, int val)
{
    tls->pha_enabled = val;
}

int tls_verify_client_post_handshake(tls *tls)
{
    if (!tls_IS_TLS13(tls)) {
        tlserr(tls_F_tls_VERIFY_CLIENT_POST_HANDSHAKE, tls_R_WRONG_tls_VERSION);
        return 0;
    }
    if (!tls->server) {
        tlserr(tls_F_tls_VERIFY_CLIENT_POST_HANDSHAKE, tls_R_NOT_SERVER);
        return 0;
    }

    if (!tls_is_init_finished(tls)) {
        tlserr(tls_F_tls_VERIFY_CLIENT_POST_HANDSHAKE, tls_R_STILL_IN_INIT);
        return 0;
    }

    switch (tls->post_handshake_auth) {
    case tls_PHA_NONE:
        tlserr(tls_F_tls_VERIFY_CLIENT_POST_HANDSHAKE, tls_R_EXTENSION_NOT_RECEIVED);
        return 0;
    default:
    case tls_PHA_EXT_SENT:
        tlserr(tls_F_tls_VERIFY_CLIENT_POST_HANDSHAKE, ERR_R_INTERNAL_ERROR);
        return 0;
    case tls_PHA_EXT_RECEIVED:
        break;
    case tls_PHA_REQUEST_PENDING:
        tlserr(tls_F_tls_VERIFY_CLIENT_POST_HANDSHAKE, tls_R_REQUEST_PENDING);
        return 0;
    case tls_PHA_REQUESTED:
        tlserr(tls_F_tls_VERIFY_CLIENT_POST_HANDSHAKE, tls_R_REQUEST_SENT);
        return 0;
    }

    tls->post_handshake_auth = tls_PHA_REQUEST_PENDING;

    /* checks verify_mode and algorithm_auth */
    if (!send_certificate_request(tls)) {
        tls->post_handshake_auth = tls_PHA_EXT_RECEIVED; /* restore on error */
        tlserr(tls_F_tls_VERIFY_CLIENT_POST_HANDSHAKE, tls_R_INVALID_CONFIG);
        return 0;
    }

    otls_statem_set_in_init(tls, 1);
    return 1;
}

int tls_CTX_set_session_ticket_cb(tls_CTX *ctx,
                                  tls_CTX_generate_session_ticket_fn gen_cb,
                                  tls_CTX_decrypt_session_ticket_fn dec_cb,
                                  void *arg)
{
    ctx->generate_ticket_cb = gen_cb;
    ctx->decrypt_ticket_cb = dec_cb;
    ctx->ticket_cb_data = arg;
    return 1;
}

void tls_CTX_set_allow_early_data_cb(tls_CTX *ctx,
                                     tls_allow_early_data_cb_fn cb,
                                     void *arg)
{
    ctx->allow_early_data_cb = cb;
    ctx->allow_early_data_cb_data = arg;
}

void tls_set_allow_early_data_cb(tls *s,
                                 tls_allow_early_data_cb_fn cb,
                                 void *arg)
{
    s->allow_early_data_cb = cb;
    s->allow_early_data_cb_data = arg;
}
