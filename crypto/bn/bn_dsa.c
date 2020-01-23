/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <openssl/opensslconf.h>
#ifdef FIPS_MODE
NON_EMPTY_TRANSLATION_UNIT
#else
# include <stdio.h>
# include <string.h>
# include <openssl/evp.h>
# include <openssl/rand_drbg.h>
# include "internal/cryptlib.h"
# include "crypto/bn.h"
# include "internal/thread_once.h"
# include "../rand/rand_local.h"

typedef struct rfc6979_seed_st {
    const unsigned char *x;
    const unsigned char *h;
    size_t rlen;
} RFC6979_SEED;

static size_t rfc6979_get_entropy(RAND_DRBG *drbg, unsigned char **pout,
                          int entropy, size_t min_len, size_t max_len,
                          int prediction_resistance)
{
    RFC6979_SEED *rfc6979_seed = RAND_DRBG_get_callback_data(drbg);

    *pout = (unsigned char *)rfc6979_seed->x;
    return rfc6979_seed->rlen;
}

static size_t rfc6979_get_nonce(RAND_DRBG *drbg, unsigned char **pout,
                        int entropy, size_t min_len, size_t max_len)
{
    RFC6979_SEED *rfc6979_seed = RAND_DRBG_get_callback_data(drbg);

    *pout = (unsigned char *)rfc6979_seed->h;
    return rfc6979_seed->rlen;
}

/*
 * RFC 6979 2.3.2.  Bit String to Integer
 */
static int bits2int(BIGNUM *out, int qlen,
    const unsigned char *message, size_t message_len)
{
    if (BN_bin2bn(message, (int)message_len, out) == NULL)
        return 0;
    if ((int)message_len * 8 > qlen)
        return BN_rshift(out, out, (int)message_len * 8 - qlen);
    return 1;
}

/*
 * RFC 6979 2.3.3.  Integer to Octet String
 */
static int int2octets(unsigned char *out, const BIGNUM *num, int rlen)
{
    return BN_bn2binpad(num, out, rlen);
}

/*
 * RFC 6979 2.3.4.  Bit String to Octet String
 */
static int bits2octets(unsigned char *out, const BIGNUM *range,
    const unsigned char *message, size_t message_len, BN_CTX *ctx)
{
    int ret = 1;
    BIGNUM *num = BN_new();

    if (!bits2int(num, BN_num_bits(range), message, message_len)
        || !BN_mod(num, num, range, ctx)
        || !BN_bn2binpad(num, out, BN_num_bytes(range)))
    {
        ret = 0;
    }

    BN_free(num);
    return ret;
}

int bn_generate_dsa_deterministic_nonce(BIGNUM *out, const BIGNUM *range,
    const BIGNUM *priv, const unsigned char *message,
    size_t message_len, int hash_type, BN_CTX *ctx)
{
    int ret = 0, rlen = 0, qlen = 0;
    RAND_DRBG *drbg = NULL;
    RFC6979_SEED rfc6979_seed = { NULL, NULL, 0 };
    unsigned int drbg_flags = RAND_DRBG_FLAG_HMAC;
    unsigned char *x = NULL, *h = NULL, *T = NULL;

    if ((qlen = BN_num_bits(range)) == 0
        || (rlen = BN_num_bytes(range)) == 0)
        goto end;

    if ((x = (unsigned char *)OPENSSL_malloc(rlen)) == NULL
        || (h = (unsigned char *)OPENSSL_malloc(rlen)) == NULL
        || (T = (unsigned char *)OPENSSL_malloc(rlen)) == NULL)
        goto end;

    if (!int2octets(x, priv, rlen)
        || !bits2octets(h, range, message, message_len, ctx))
        goto end;

    rfc6979_seed.x = x;
    rfc6979_seed.h = h;
    rfc6979_seed.rlen = rlen;

    if ((drbg = RAND_DRBG_new(hash_type, drbg_flags, NULL)) == NULL
        || !RAND_DRBG_set_callbacks(drbg, rfc6979_get_entropy, NULL, rfc6979_get_nonce, NULL)
        || !RAND_DRBG_set_callback_data(drbg, &rfc6979_seed))
        goto end;

    /* TODO(3.0): Rewrite the following two lines and include "../rand/rand_lcl.h" if drbg min_lengths can be set using methods */
    drbg->min_entropylen = rlen;
    drbg->min_noncelen = rlen;

    if (!RAND_DRBG_instantiate(drbg, NULL, 0))
        goto end;

    while (1)
    {
        if (!RAND_DRBG_generate(drbg, T, rlen, 0, NULL, 0)
            || !bits2int(out, qlen, T, rlen))
            goto end;
        if ((!BN_is_zero(out)) && (!BN_is_one(out)) && (BN_cmp(out, range) < 0))
            break;
    }
    ret = 1;

end:
    RAND_DRBG_uninstantiate(drbg);
    RAND_DRBG_free(drbg);
    OPENSSL_clear_free(x, rlen);
    OPENSSL_free(h);
    OPENSSL_clear_free(T, rlen);
    return ret;
}
#endif
