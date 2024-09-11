/*
 * Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
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

/*
 * Each node in a LMS tree has a node id associated with it.
 * Starting with 1 at the top of the tree. The children have node id's
 * of 2 and 3, then next level uses 4, 5, 6, 7 etc.
 * A value of 64 allows the 5 top levels of a single LMS tree to be
 * entirely cached.
 *
 * Changing this value to a higher limit requires changes to the code since it
 * currently just uses the 64 bits key->cachebits to tell if a node is hashed.
 * Note that it subtracts 1 to get the id's in the range 0..63.
 *
 * A LMS tree has OTS public keys in its leaf nodes (as well as private keys).
 * The public key of any non leaf node in the tree is calculated as some Hash
 * of the children's public keys. The public key of the LMS tree is the
 * public key at the top of the tree. We therefore need to generate key pairs
 * for the entire LMS tree in order to figure out the public key.
 *
 * The public keys for lower nodes will not be cached, but they are calculated
 * less often than the top nodes of the tree.
 */
#define OSSL_LMS_PUBKEY_CACHE_SIZE 64

/**
 * @brief Create a cache object for storing hashes related to public keys
 *
 * @param key A LMS tree to add a cache to.
 * @returns 1 if the cache was created, otherwise it returns 0.
 */
int ossl_lms_pubkey_cache_new(LMS_KEY *key)
{
    key->cachebits = 0;
    /* The size of each hash is n */
    key->node_cache = OPENSSL_malloc(key->lms_params->n * OSSL_LMS_PUBKEY_CACHE_SIZE);
    return (key->node_cache != NULL);
}

/**
 * @brief Destroy a cache object.
 *
 * @param key A LMS tree containing a node cache.
 * @returns 1 if the cache was created, otherwise it returns 0.
 */
void ossl_lms_pubkey_cache_free(LMS_KEY *key)
{
    OPENSSL_free(key->node_cache);
    key->node_cache = NULL;
}

/**
 * @brief Flush the cache object.
 * This simply just clears the used bits.
 */
void ossl_lms_pubkey_cache_flush(LMS_KEY *key)
{
    key->cachebits = 0;
}

/**
 * @brief Add a public key hash to the cache.
 *
 * @param key The LMS_KEY containing a cache
 * @param nodeId The key id to add a hash to. Values not in the range 1..64
 *               are ignored.
 * @param data A public key byte array of size |n| to add to the cache.
 */
void ossl_lms_pubkey_cache_add(LMS_KEY *key, uint32_t nodeid,
                               const unsigned char *data)
{
    if (nodeid == 0 || nodeid > 64)
        return;
    --nodeid; /* 0..63 */
    key->cachebits |= ((uint64_t)1 << (nodeid));
    memcpy(key->node_cache + nodeid * key->lms_params->n, data,
           key->lms_params->n);
}

/**
 * @brief Retrieve an existing public key hash from the cache.
 *
 * @param key The LMS_KEY containing a cache
 * @param nodeId The key id get the hash from. Values not in the range 1..64
 *               produce an error.
 * @param out A pointer to the returned byte array of size |n|
 * @returns 1 if the public key hash could be retrieved, or 0 on failure.
 */
int ossl_lms_pubkey_cache_get(LMS_KEY *key, uint32_t nodeid, unsigned char *out)
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

#if !defined(OPENSSL_NO_HSS_GEN) && !defined(FIPS_MODULE)
/**
 * @brief Copy the cache from an existing LMS_KEY to a new LMS_KEY
 *
 * @params src The LMS_KEY to copy from
 * @params dst The LMS_KEY to copy to
 * @returns 1 if the caches was successfully copied, or 0 on failure.
 */
int ossl_lms_pubkey_cache_copy(LMS_KEY *dst, const LMS_KEY *src)
{
    if (!ossl_lms_pubkey_cache_new(dst))
        return 0;
    dst->cachebits = src->cachebits;
    memcpy(dst->node_cache, src->node_cache, src->lms_params->n * 64);
    return 1;
}
#endif /* OPENSSL_NO_HSS_GEN */
