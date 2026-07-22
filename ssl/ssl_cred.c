/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "internal/pool.h"
#include "internal/refcount.h"

#include "ssl_local.h"

SSL_CREDENTIAL *ossl_ssl_credential_new(SSL_CREDENTIAL_TYPE type)
{
    SSL_CREDENTIAL *cred;

    if ((cred = OPENSSL_zalloc(sizeof(*cred))) == NULL)
        return NULL;
    cred->type = type;
    if (!CRYPTO_NEW_REF(&cred->references, 1)) {
        OPENSSL_free(cred);
        return NULL;
    }
    return cred;
}

int ossl_ssl_credential_set1_cert_chain(SSL_CREDENTIAL *cred,
    STACK_OF(CRYPTO_BUFFER) *chain)
{
    STACK_OF(CRYPTO_BUFFER) *copy = NULL;
    int i;

    if (chain != NULL) {
        if ((copy = sk_CRYPTO_BUFFER_dup(chain)) == NULL)
            return 0;
        for (i = 0; i < sk_CRYPTO_BUFFER_num(copy); i++) {
            if (!CRYPTO_BUFFER_up_ref(sk_CRYPTO_BUFFER_value(copy, i))) {
                while (--i >= 0)
                    CRYPTO_BUFFER_free(sk_CRYPTO_BUFFER_value(copy, i));
                sk_CRYPTO_BUFFER_free(copy);
                return 0;
            }
        }
    }
    sk_CRYPTO_BUFFER_pop_free(cred->chain, CRYPTO_BUFFER_free);
    cred->chain = copy;
    return 1;
}

int ossl_ssl_credential_set1_private_key(SSL_CREDENTIAL *cred, EVP_PKEY *pkey)
{
    if (pkey != NULL && !EVP_PKEY_up_ref(pkey))
        return 0;
    EVP_PKEY_free(cred->pkey);
    cred->pkey = pkey;
    return 1;
}

int ossl_ssl_credential_set1_trust_anchor_id(SSL_CREDENTIAL *cred,
    const uint8_t *id, size_t id_len)
{
    uint8_t *copy = NULL;

    if (id_len != 0 && (copy = OPENSSL_memdup(id, id_len)) == NULL)
        return 0;
    OPENSSL_free(cred->trust_anchor_id);
    cred->trust_anchor_id = copy;
    cred->trust_anchor_id_len = id_len;
    return 1;
}

int ossl_ssl_credential_add1_trust_anchor_group(SSL_CREDENTIAL *cred,
    const uint8_t *pattern, size_t pattern_len)
{
    SSL_TRUST_ANCHOR_PATTERN *groups;
    uint8_t *copy = NULL;

    if (pattern_len != 0
        && (copy = OPENSSL_memdup(pattern, pattern_len)) == NULL)
        return 0;
    groups = OPENSSL_realloc_array(cred->groups, cred->group_count + 1,
        sizeof(*groups));
    if (groups == NULL) {
        OPENSSL_free(copy);
        return 0;
    }
    cred->groups = groups;
    groups[cred->group_count].pattern = copy;
    groups[cred->group_count].pattern_len = pattern_len;
    cred->group_count++;
    return 1;
}

int SSL_CREDENTIAL_up_ref(SSL_CREDENTIAL *cred)
{
    int i;

    if (cred == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    return CRYPTO_UP_REF(&cred->references, &i);
}

void SSL_CREDENTIAL_free(SSL_CREDENTIAL *cred)
{
    int i;
    size_t j;

    if (cred == NULL)
        return;
    CRYPTO_DOWN_REF(&cred->references, &i);
    REF_PRINT_COUNT("SSL_CREDENTIAL", i, cred);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    sk_CRYPTO_BUFFER_pop_free(cred->chain, CRYPTO_BUFFER_free);
    EVP_PKEY_free(cred->pkey);
    OPENSSL_free(cred->trust_anchor_id);
    for (j = 0; j < cred->group_count; j++)
        OPENSSL_free(cred->groups[j].pattern);
    OPENSSL_free(cred->groups);
    CRYPTO_FREE_REF(&cred->references);
    OPENSSL_free(cred);
}

int SSL_CTX_add1_credential(SSL_CTX *ctx, SSL_CREDENTIAL *cred)
{
    if (ctx == NULL || cred == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (ctx->cert->credentials == NULL
        && (ctx->cert->credentials = sk_SSL_CREDENTIAL_new_null()) == NULL)
        return 0;
    if (!SSL_CREDENTIAL_up_ref(cred))
        return 0;
    if (sk_SSL_CREDENTIAL_push(ctx->cert->credentials, cred) <= 0) {
        SSL_CREDENTIAL_free(cred);
        ERR_raise(ERR_LIB_SSL, ERR_R_CRYPTO_LIB);
        return 0;
    }
    return 1;
}
