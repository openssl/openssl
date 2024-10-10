/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/ech.h>
#include "../ssl_local.h"
#include "ech_local.h"

#ifndef OPENSSL_NO_ECH

/* ECH internal API functions */

static OSSL_ECHSTORE_ENTRY *ossl_echstore_entry_dup(OSSL_ECHSTORE_ENTRY *orig)
{
    OSSL_ECHSTORE_ENTRY *ret = NULL;
    OSSL_ECHEXT *ext = NULL, *newext = NULL;
    int i;

    if (orig == NULL)
        return NULL;
    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL)
        return NULL;
    ret->version = orig->version;
    if (orig->public_name != NULL) {
        ret->public_name = OPENSSL_strdup(orig->public_name);
        if (ret->public_name == NULL)
            goto err;
    }
    ret->pub_len = orig->pub_len;
    if (orig->pub != NULL) {
        ret->pub = OPENSSL_memdup(orig->pub, orig->pub_len);
        if (ret->pub == NULL)
            goto err;
    }
    ret->nsuites = orig->nsuites;
    ret->suites = OPENSSL_memdup(orig->suites, sizeof(OSSL_HPKE_SUITE) * ret->nsuites);
    if (ret->suites == NULL)
        goto err;
    ret->max_name_length = orig->max_name_length;
    ret->config_id = orig->config_id;
    if (orig->exts != NULL) {
        int num;

        if ((ret->exts = sk_OSSL_ECHEXT_new_null()) == NULL)
            goto err;
        num = (orig->exts == NULL ? 0 : sk_OSSL_ECHEXT_num(orig->exts));
        for (i = 0; i != num; i++) {
            ext = sk_OSSL_ECHEXT_value(orig->exts, i);
            if (ext == NULL)
                goto err;
            newext = OPENSSL_malloc(sizeof(OSSL_ECHEXT));
            if (newext == NULL)
                goto err;
            newext->type = ext->type;
            newext->len = ext->len;
            newext->val = NULL;
            if (ext->len != 0) {
                newext->val = OPENSSL_memdup(ext->val, ext->len);
                if (newext->val == NULL)
                    goto err;
            }
            if (sk_OSSL_ECHEXT_insert(ret->exts, newext, i) == 0) {
                OPENSSL_free(newext->val);
                OPENSSL_free(newext);
                goto err;
            }
        }
    }
    ret->loadtime = orig->loadtime;
    if (orig->keyshare != NULL) {
        ret->keyshare = orig->keyshare;
        EVP_PKEY_up_ref(orig->keyshare);
    }
    ret->for_retry = orig->for_retry;
    if (orig->encoded != NULL) {
        ret->encoded_len = orig->encoded_len;
        ret->encoded = OPENSSL_memdup(orig->encoded, ret->encoded_len);
        if (ret->encoded == NULL)
            goto err;
    }
    return ret;
err:
    ossl_echstore_entry_free(ret);
    return NULL;
}

/* duplicate an OSSL_ECHSTORE as needed */
int ossl_echstore_dup(OSSL_ECHSTORE **new, OSSL_ECHSTORE *old)
{
    OSSL_ECHSTORE *cp = NULL;
    OSSL_ECHSTORE_ENTRY *ee = NULL;
    int i, num;

    if (new == NULL || old == NULL)
        return 0;
    cp = OPENSSL_zalloc(sizeof(*cp));
    if (cp == NULL)
        return 0;
    cp->libctx = old->libctx;
    cp->propq = old->propq;
    if (old->entries == NULL) {
        *new = cp;
        return 1;
    }
    if ((cp->entries = sk_OSSL_ECHSTORE_ENTRY_new_null()) == NULL)
        goto err;
    num = sk_OSSL_ECHSTORE_ENTRY_num(old->entries);
    for (i = 0; i != num; i++) {
        ee = ossl_echstore_entry_dup(sk_OSSL_ECHSTORE_ENTRY_value(old->entries,
                                                                  i));
        if (ee == NULL)
            goto err;
        if (sk_OSSL_ECHSTORE_ENTRY_insert(cp->entries, ee, i) == 0)
            goto err;
    }
    *new = cp;
    return 1;
err:
    OSSL_ECHSTORE_free(cp);
    ossl_echstore_entry_free(ee);
    return 0;
}

void ossl_ctx_ech_free(OSSL_CTX_ECH *ce)
{
    if (ce == NULL)
        return;
    OSSL_ECHSTORE_free(ce->es);
    OPENSSL_free(ce->alpn_outer);
    return;
}

void ossl_ech_conn_free(OSSL_ECH_CONN *ec)
{
    if (ec == NULL)
        return;
    OSSL_ECHSTORE_free(ec->es);
    OPENSSL_free(ec->outer_hostname);
    OPENSSL_free(ec->alpn_outer);
    OPENSSL_free(ec->former_inner);
    OPENSSL_free(ec->innerch);
    OPENSSL_free(ec->encoded_innerch);
    OPENSSL_free(ec->innerch1);
    OPENSSL_free(ec->kepthrr);
    OPENSSL_free(ec->grease_suite);
    OPENSSL_free(ec->sent);
    OPENSSL_free(ec->returned);
    OPENSSL_free(ec->pub);
    OSSL_HPKE_CTX_free(ec->hpke_ctx);
    EVP_PKEY_free(ec->tmp_pkey);
    return;
}

/* called from ssl/ssl_lib.c: ossl_ssl_connection_new_int */
int ossl_ech_conn_init(SSL_CONNECTION *s, SSL_CTX *ctx,
                       const SSL_METHOD *method)
{
    OSSL_ECHSTORE *new = NULL;

    memset(&s->ext.ech, 0, sizeof(s->ext.ech));
    if (ctx->ext.ech.es != NULL && !ossl_echstore_dup(&new, ctx->ext.ech.es))
        goto err;
    s->ext.ech.es = new;
    new = NULL;
    s->ext.ech.cb = ctx->ext.ech.cb;
    if (ctx->ext.ech.alpn_outer != NULL) {
        s->ext.ech.alpn_outer = OPENSSL_memdup(ctx->ext.ech.alpn_outer,
                                               ctx->ext.ech.alpn_outer_len);
        if (s->ext.ech.alpn_outer == NULL)
            goto err;
        s->ext.ech.alpn_outer_len = ctx->ext.ech.alpn_outer_len;
    }
    /* initialise type/cid to unknown */
    s->ext.ech.attempted_type = TLSEXT_TYPE_ech_unknown;
    s->ext.ech.attempted_cid = TLSEXT_TYPE_ech_config_id_unset;
    if (s->ext.ech.es != NULL)
        s->ext.ech.attempted = 1;
    if (ctx->options & SSL_OP_ECH_GREASE)
        s->options |= SSL_OP_ECH_GREASE;
    return 1;
err:
    OSSL_ECHSTORE_free(s->ext.ech.es);
    OPENSSL_free(s->ext.ech.alpn_outer);
    return 0;
}

#endif
