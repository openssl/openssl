/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>
#include "lms_local.h"
#include "internal/refcount.h"

int ossl_lms_key_node_cache_init(LMS_KEY *key)
{
    key->cachebits = 0;
    key->node_cache = OPENSSL_malloc(key->lms_params->n * 64);
    return (key->node_cache != NULL);
}

int ossl_lms_key_node_cache_copy(const LMS_KEY *src, LMS_KEY *dst)
{
    if (!ossl_lms_key_node_cache_init(dst))
        return 0;
    dst->cachebits = src->cachebits;
    memcpy(dst->node_cache, src->node_cache, src->lms_params->n * 64);
    return 1;
}

void ossl_lms_key_node_cache_final(LMS_KEY *key)
{
    OPENSSL_free(key->node_cache);
}

void ossl_lms_key_node_cache_flush(LMS_KEY *key)
{
    key->cachebits = 0;
}

void ossl_lms_key_node_cache_add(LMS_KEY *key, uint32_t nodeid,
                                 const unsigned char *data)
{
    if (nodeid == 0 || nodeid > 64)
        return;
    --nodeid;
    key->cachebits |= ((uint64_t)1 << (nodeid));
    memcpy(key->node_cache + nodeid * key->lms_params->n, data,
           key->lms_params->n);
}

int ossl_lms_key_node_cache_get(LMS_KEY *key, uint32_t nodeid,
                                unsigned char *out)
{
    if (nodeid == 0 || nodeid > 64)
        return 0;
    --nodeid;
    if ((key->cachebits & ((uint64_t)1 << nodeid)) != 0) {
        memcpy(out, key->node_cache + nodeid * key->lms_params->n,
               key->lms_params->n);
        return 1;
    } else {
        return 0;
    }
}
