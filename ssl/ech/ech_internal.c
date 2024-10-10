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

static OSSL_ECHSTORE_ENTRY *ossl_echstore_entry_dup(const OSSL_ECHSTORE_ENTRY *orig)
{
    OSSL_ECHSTORE_ENTRY *ret = NULL;

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
        ret->exts = sk_OSSL_ECHEXT_deep_copy(orig->exts, ossl_echext_dup,
                                             ossl_echext_free);
        if (ret->exts == NULL)
            goto err;
    }
    ret->loadtime = orig->loadtime;
    if (orig->keyshare != NULL) {
        if (!EVP_PKEY_up_ref(orig->keyshare))
            goto err;
        ret->keyshare = orig->keyshare;
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
OSSL_ECHSTORE *ossl_echstore_dup(const OSSL_ECHSTORE *old)
{
    OSSL_ECHSTORE *cp = NULL;

    if (old == NULL)
        return NULL;
    cp = OPENSSL_zalloc(sizeof(*cp));
    if (cp == NULL)
        return NULL;
    cp->libctx = old->libctx;
    if (old->propq != NULL) {
        cp->propq = OPENSSL_strdup(old->propq);
        if (cp->propq == NULL)
            goto err;
    }
    if (old->entries != NULL) {
        cp->entries = sk_OSSL_ECHSTORE_ENTRY_deep_copy(old->entries,
                                                       ossl_echstore_entry_dup,
                                                       ossl_echstore_entry_free);
        if (cp->entries == NULL)
            goto err;
    }
    return cp;
err:
    OSSL_ECHSTORE_free(cp);
    return NULL;
}

void ossl_ech_ctx_clear(OSSL_ECH_CTX *ce)
{
    if (ce == NULL)
        return;
    OSSL_ECHSTORE_free(ce->es);
    OPENSSL_free(ce->alpn_outer);
    return;
}

void ossl_ech_conn_clear(OSSL_ECH_CONN *ec)
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
    memset(&s->ext.ech, 0, sizeof(s->ext.ech));
    if (ctx->ext.ech.es != NULL
        && (s->ext.ech.es = ossl_echstore_dup(ctx->ext.ech.es)) == NULL)
        goto err;
    s->ext.ech.cb = ctx->ext.ech.cb;
    if (ctx->ext.ech.alpn_outer != NULL) {
        s->ext.ech.alpn_outer = OPENSSL_memdup(ctx->ext.ech.alpn_outer,
                                               ctx->ext.ech.alpn_outer_len);
        if (s->ext.ech.alpn_outer == NULL)
            goto err;
        s->ext.ech.alpn_outer_len = ctx->ext.ech.alpn_outer_len;
    }
    /* initialise type/cid to unknown */
    s->ext.ech.attempted_type = OSSL_ECH_type_unknown;
    s->ext.ech.attempted_cid = OSSL_ECH_config_id_unset;
    if (s->ext.ech.es != NULL)
        s->ext.ech.attempted = 1;
    if (ctx->options & SSL_OP_ECH_GREASE)
        s->options |= SSL_OP_ECH_GREASE;
    return 1;
err:
    OSSL_ECHSTORE_free(s->ext.ech.es);
    s->ext.ech.es = NULL;
    OPENSSL_free(s->ext.ech.alpn_outer);
    s->ext.ech.alpn_outer = NULL;
    s->ext.ech.alpn_outer_len = 0;
    return 0;
}

#endif
