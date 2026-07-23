/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

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

/*
 * Remove an encoded base-128 integer from the front of in, leaving its
 * encoding in out (section 5.3.1 of
 * https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids-05/).
 * Fails if in is empty, or the integer is not minimally encoded or is
 * truncated.
 */
static int pattern_get_int(PACKET *in, PACKET *out)
{
    const unsigned char *data = PACKET_data(in);
    size_t len = PACKET_remaining(in), i;

    if (len == 0 || data[0] == 0x80)
        return 0;
    for (i = 0; i < len && (data[i] & 0x80) != 0; i++)
        continue;
    if (i == len)
        return 0;
    return PACKET_get_sub_packet(in, out, i + 1);
}

/*
 * Compare two encoded base-128 integers, returning a negative, zero or
 * positive value as a is less than, equal to or greater than b.  A minimal
 * encoding orders by length, then by bytes.
 */
static int pattern_int_cmp(const PACKET *a, const PACKET *b)
{
    if (PACKET_remaining(a) != PACKET_remaining(b))
        return PACKET_remaining(a) < PACKET_remaining(b) ? -1 : 1;
    return memcmp(PACKET_data(a), PACKET_data(b), PACKET_remaining(a));
}

int ossl_ssl_trust_anchor_pattern_contains(const uint8_t *pattern,
    size_t pattern_len, const uint8_t *id, size_t id_len)
{
    PACKET pat, in, v, min, max;
    unsigned int b;

    if (!PACKET_buf_init(&pat, pattern, pattern_len)
        || !PACKET_buf_init(&in, id, id_len))
        return 0;
    while (PACKET_remaining(&in) > 0) {
        if (!pattern_get_int(&in, &v)
            || !pattern_get_int(&pat, &min)
            || pattern_int_cmp(&v, &min) < 0)
            return 0;
        /* A max of infinity is the single byte 0x80. */
        if (PACKET_peek_1(&pat, &b) && b == 0x80 && PACKET_forward(&pat, 1))
            continue;
        if (!pattern_get_int(&pat, &max) || pattern_int_cmp(&max, &v) < 0)
            return 0;
    }
    return PACKET_remaining(&pat) == 0;
}

int ossl_ssl_credential_matches_request(const SSL_CREDENTIAL *cred,
    const uint8_t *ids, size_t ids_len)
{
    PACKET list, id;
    size_t i;

    if (!PACKET_buf_init(&list, ids, ids_len))
        return 0;
    while (PACKET_remaining(&list) > 0) {
        /* The list was validated when it was parsed. */
        if (!PACKET_get_length_prefixed_1(&list, &id))
            return 0;
        if (cred->trust_anchor_id != NULL
            && PACKET_remaining(&id) == cred->trust_anchor_id_len
            && memcmp(PACKET_data(&id), cred->trust_anchor_id,
                   cred->trust_anchor_id_len)
                == 0)
            return 1;
        for (i = 0; i < cred->group_count; i++)
            if (ossl_ssl_trust_anchor_pattern_contains(cred->groups[i].pattern,
                    cred->groups[i].pattern_len, PACKET_data(&id),
                    PACKET_remaining(&id)))
                return 1;
    }

    return 0;
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
