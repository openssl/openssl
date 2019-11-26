/*
 * Copyright 2011-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include "internal/param_build.h"
#include "internal/thread_once.h"
#include "prov/providercommon.h"
#include "drbg_local.h"

/*
 * The state of a DRBG AES-CTR.
 */
typedef struct rand_drbg_ctr_st {
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER_CTX *ctx_df;
    PROV_CIPHER cipher;
    size_t keylen;
    int df;
    unsigned char K[32];
    unsigned char V[16];
    /* Temporary block storage used by ctr_df */
    unsigned char bltmp[16];
    size_t bltmp_pos;
    unsigned char KX[48];
} PROV_RAND_CTR;

/*
 * Implementation of NIST SP 800-90A CTR DRBG.
 */
static void inc_128(PROV_RAND_CTR *ctr)
{
    int i;
    unsigned char c;
    unsigned char *p = &ctr->V[15];

    for (i = 0; i < 16; i++, p--) {
        c = *p;
        c++;
        *p = c;
        if (c != 0) {
            /* If we didn't wrap around, we're done. */
            break;
        }
    }
}

static void ctr_XOR(PROV_RAND_CTR *ctr, const unsigned char *in, size_t inlen)
{
    size_t i, n;

    if (in == NULL || inlen == 0)
        return;

    /*
     * Any zero padding will have no effect on the result as we
     * are XORing. So just process however much input we have.
     */
    n = inlen < ctr->keylen ? inlen : ctr->keylen;
    for (i = 0; i < n; i++)
        ctr->K[i] ^= in[i];
    if (inlen <= ctr->keylen)
        return;

    n = inlen - ctr->keylen;
    if (n > 16) {
        /* Should never happen */
        n = 16;
    }
    for (i = 0; i < n; i++)
        ctr->V[i] ^= in[i + ctr->keylen];
}

/*
 * Process a complete block using BCC algorithm of SP 800-90A 10.3.3
 */
__owur static int ctr_BCC_block(PROV_RAND_CTR *ctr, unsigned char *out,
                                const unsigned char *in)
{
    int i, outlen = AES_BLOCK_SIZE;

    for (i = 0; i < 16; i++)
        out[i] ^= in[i];

    if (!EVP_CipherUpdate(ctr->ctx_df, out, &outlen, out, AES_BLOCK_SIZE)
        || outlen != AES_BLOCK_SIZE)
        return 0;
    return 1;
}


/*
 * Handle several BCC operations for as much data as we need for K and X
 */
__owur static int ctr_BCC_blocks(PROV_RAND_CTR *ctr, const unsigned char *in)
{
    if (!ctr_BCC_block(ctr, ctr->KX, in)
        || !ctr_BCC_block(ctr, ctr->KX + 16, in))
        return 0;
    if (ctr->keylen != 16 && !ctr_BCC_block(ctr, ctr->KX + 32, in))
        return 0;
    return 1;
}

/*
 * Initialise BCC blocks: these have the value 0,1,2 in leftmost positions:
 * see 10.3.1 stage 7.
 */
__owur static int ctr_BCC_init(PROV_RAND_CTR *ctr)
{
    memset(ctr->KX, 0, 48);
    memset(ctr->bltmp, 0, 16);
    if (!ctr_BCC_block(ctr, ctr->KX, ctr->bltmp))
        return 0;
    ctr->bltmp[3] = 1;
    if (!ctr_BCC_block(ctr, ctr->KX + 16, ctr->bltmp))
        return 0;
    if (ctr->keylen != 16) {
        ctr->bltmp[3] = 2;
        if (!ctr_BCC_block(ctr, ctr->KX + 32, ctr->bltmp))
            return 0;
    }
    return 1;
}

/*
 * Process several blocks into BCC algorithm, some possibly partial
 */
__owur static int ctr_BCC_update(PROV_RAND_CTR *ctr,
                                 const unsigned char *in, size_t inlen)
{
    if (in == NULL || inlen == 0)
        return 1;

    /* If we have partial block handle it first */
    if (ctr->bltmp_pos) {
        size_t left = 16 - ctr->bltmp_pos;

        /* If we now have a complete block process it */
        if (inlen >= left) {
            memcpy(ctr->bltmp + ctr->bltmp_pos, in, left);
            if (!ctr_BCC_blocks(ctr, ctr->bltmp))
                return 0;
            ctr->bltmp_pos = 0;
            inlen -= left;
            in += left;
        }
    }

    /* Process zero or more complete blocks */
    for (; inlen >= 16; in += 16, inlen -= 16) {
        if (!ctr_BCC_blocks(ctr, in))
            return 0;
    }

    /* Copy any remaining partial block to the temporary buffer */
    if (inlen > 0) {
        memcpy(ctr->bltmp + ctr->bltmp_pos, in, inlen);
        ctr->bltmp_pos += inlen;
    }
    return 1;
}

__owur static int ctr_BCC_final(PROV_RAND_CTR *ctr)
{
    if (ctr->bltmp_pos) {
        memset(ctr->bltmp + ctr->bltmp_pos, 0, 16 - ctr->bltmp_pos);
        if (!ctr_BCC_blocks(ctr, ctr->bltmp))
            return 0;
    }
    return 1;
}

__owur static int ctr_df(PROV_RAND_CTR *ctr,
                         const unsigned char *in1, size_t in1len,
                         const unsigned char *in2, size_t in2len,
                         const unsigned char *in3, size_t in3len)
{
    static unsigned char c80 = 0x80;
    size_t inlen;
    unsigned char *p = ctr->bltmp;
    int outlen = AES_BLOCK_SIZE;
    const EVP_CIPHER *cipher = ossl_prov_cipher_cipher(&ctr->cipher);

    if (!ctr_BCC_init(ctr))
        return 0;
    if (in1 == NULL)
        in1len = 0;
    if (in2 == NULL)
        in2len = 0;
    if (in3 == NULL)
        in3len = 0;
    inlen = in1len + in2len + in3len;
    /* Initialise L||N in temporary block */
    *p++ = (inlen >> 24) & 0xff;
    *p++ = (inlen >> 16) & 0xff;
    *p++ = (inlen >> 8) & 0xff;
    *p++ = inlen & 0xff;

    /* NB keylen is at most 32 bytes */
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p = (unsigned char)((ctr->keylen + 16) & 0xff);
    ctr->bltmp_pos = 8;
    if (!ctr_BCC_update(ctr, in1, in1len)
        || !ctr_BCC_update(ctr, in2, in2len)
        || !ctr_BCC_update(ctr, in3, in3len)
        || !ctr_BCC_update(ctr, &c80, 1)
        || !ctr_BCC_final(ctr))
        return 0;
    /* Set up key K */
    if (!EVP_CipherInit_ex(ctr->ctx, cipher, NULL, ctr->KX, NULL, 1))
        return 0;
    /* X follows key K */
    if (!EVP_CipherUpdate(ctr->ctx, ctr->KX, &outlen, ctr->KX + ctr->keylen,
                          AES_BLOCK_SIZE)
        || outlen != AES_BLOCK_SIZE)
        return 0;
    if (!EVP_CipherUpdate(ctr->ctx, ctr->KX + 16, &outlen, ctr->KX,
                          AES_BLOCK_SIZE)
        || outlen != AES_BLOCK_SIZE)
        return 0;
    if (ctr->keylen != 16)
        if (!EVP_CipherUpdate(ctr->ctx, ctr->KX + 32, &outlen, ctr->KX + 16,
                              AES_BLOCK_SIZE)
            || outlen != AES_BLOCK_SIZE)
            return 0;
    return 1;
}

/*
 * NB the no-df Update in SP800-90A specifies a constant input length
 * of seedlen, however other uses of this algorithm pad the input with
 * zeroes if necessary and have up to two parameters XORed together,
 * so we handle both cases in this function instead.
 */
__owur static int ctr_update(PROV_RAND *drbg,
                             const unsigned char *in1, size_t in1len,
                             const unsigned char *in2, size_t in2len,
                             const unsigned char *nonce, size_t noncelen)
{
    PROV_RAND_CTR *ctr = (PROV_RAND_CTR *)drbg->data;
    int outlen = AES_BLOCK_SIZE;
    const EVP_CIPHER *cipher = ossl_prov_cipher_cipher(&ctr->cipher);

    /* correct key is already set up. */
    inc_128(ctr);
    if (!EVP_CipherUpdate(ctr->ctx, ctr->K, &outlen, ctr->V, AES_BLOCK_SIZE)
        || outlen != AES_BLOCK_SIZE)
        return 0;

    /* If keylen longer than 128 bits need extra encrypt */
    if (ctr->keylen != 16) {
        inc_128(ctr);
        if (!EVP_CipherUpdate(ctr->ctx, ctr->K+16, &outlen, ctr->V,
                              AES_BLOCK_SIZE)
            || outlen != AES_BLOCK_SIZE)
            return 0;
    }
    inc_128(ctr);
    if (!EVP_CipherUpdate(ctr->ctx, ctr->V, &outlen, ctr->V, AES_BLOCK_SIZE)
        || outlen != AES_BLOCK_SIZE)
        return 0;

    /* If 192 bit key part of V is on end of K */
    if (ctr->keylen == 24) {
        memcpy(ctr->V + 8, ctr->V, 8);
        memcpy(ctr->V, ctr->K + 24, 8);
    }

    if (ctr->df) {
        /* If no input reuse existing derived value */
        if (in1 != NULL || nonce != NULL || in2 != NULL)
            if (!ctr_df(ctr, in1, in1len, nonce, noncelen, in2, in2len))
                return 0;
        /* If this a reuse input in1len != 0 */
        if (in1len)
            ctr_XOR(ctr, ctr->KX, drbg->seedlen);
    } else {
        ctr_XOR(ctr, in1, in1len);
        ctr_XOR(ctr, in2, in2len);
    }

    if (!EVP_CipherInit_ex(ctr->ctx, cipher, NULL, ctr->K, NULL, 1))
        return 0;
    return 1;
}

__owur static int drbg_ctr_instantiate(void *vctx,
                                       const unsigned char *entropy, size_t entropylen,
                                       const unsigned char *nonce, size_t noncelen,
                                       const unsigned char *pers, size_t perslen)
{
    PROV_RAND *ctx = (PROV_RAND *)vctx;
    PROV_RAND_CTR *ctr = (PROV_RAND_CTR *)ctx->data;
    const EVP_CIPHER *cipher = ossl_prov_cipher_cipher(&ctr->cipher);

    if (entropy == NULL)
        return 0;

    memset(ctr->K, 0, sizeof(ctr->K));
    memset(ctr->V, 0, sizeof(ctr->V));
    if (!EVP_CipherInit_ex(ctr->ctx, cipher, NULL, ctr->K, NULL, 1))
        return 0;
    if (!ctr_update(ctx, entropy, entropylen, pers, perslen, nonce, noncelen))
        return 0;
    return 1;
}

__owur static int drbg_ctr_reseed(void *vctx,
                                  const unsigned char *entropy, size_t entropylen,
                                  const unsigned char *adin, size_t adinlen)
{
    PROV_RAND *ctx = (PROV_RAND *)vctx;

    return entropy != NULL
           && ctr_update(ctx, entropy, entropylen, adin, adinlen, NULL, 0);
}

__owur static int drbg_ctr_generate(void *vctx,
                                    unsigned char *out, size_t outlen,
                                    const unsigned char *adin, size_t adinlen)
{
    PROV_RAND *ctx = (PROV_RAND *)vctx;
    PROV_RAND_CTR *ctr = (PROV_RAND_CTR *)ctx->data;

    if (adin != NULL && adinlen != 0) {
        if (!ctr_update(ctx, adin, adinlen, NULL, 0, NULL, 0))
            return 0;
        /* This means we reuse derived value */
        if (ctr->df) {
            adin = NULL;
            adinlen = 1;
        }
    } else {
        adinlen = 0;
    }

    for ( ; ; ) {
        int outl = AES_BLOCK_SIZE;

        inc_128(ctr);
        if (outlen < 16) {
            /* Use K as temp space as it will be updated */
            if (!EVP_CipherUpdate(ctr->ctx, ctr->K, &outl, ctr->V,
                                  AES_BLOCK_SIZE)
                || outl != AES_BLOCK_SIZE)
                return 0;
            memcpy(out, ctr->K, outlen);
            break;
        }
        if (!EVP_CipherUpdate(ctr->ctx, out, &outl, ctr->V, AES_BLOCK_SIZE)
            || outl != AES_BLOCK_SIZE)
            return 0;
        out += 16;
        outlen -= 16;
        if (outlen == 0)
            break;
    }

    if (!ctr_update(ctx, adin, adinlen, NULL, 0, NULL, 0))
        return 0;
    return 1;
}

static int drbg_ctr_uninstantiate(void *vctx)
{
    PROV_RAND *ctx = (PROV_RAND *)vctx;
    PROV_RAND_CTR *ctr = (PROV_RAND_CTR *)ctx->data;

    EVP_CIPHER_CTX_free(ctr->ctx);
    EVP_CIPHER_CTX_free(ctr->ctx_df);
    ossl_prov_cipher_reset(&ctr->cipher);
    OPENSSL_cleanse(ctr, sizeof(*ctr));
    return 1;
}

static int drbg_ctr_new(PROV_RAND *ctx, int df)
{
    PROV_RAND_CTR *ctr;

#ifdef FIPS_MODE
    if (!df) {
        ERR_raise(ERR_LIB_PROV, RAND_R_DERIVATION_FUNCTION_MANDATORY_FOR_FIPS);
        return 0;
    }
#endif
    ctr = ctx->secure ? OPENSSL_secure_zalloc(sizeof(*ctr))
                      : OPENSSL_zalloc(sizeof(*ctr));
    if (ctr == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    ctx->data = ctr;
    if (df) {
        ctx->max_entropylen = DRBG_MAX_LENGTH;
        ctx->max_noncelen = DRBG_MAX_LENGTH;
        ctx->max_perslen = DRBG_MAX_LENGTH;
        ctx->max_adinlen = DRBG_MAX_LENGTH;
    }
    ctx->max_request = 1 << 16;
    return 1;
#if 0
    switch (drbg->type) {
    default:
        /* This can't happen, but silence the compiler warning. */
        return 0;
    case NID_aes_128_ctr:
        keylen = 16;
        cipher = EVP_CIPHER_fetch(drbg->libctx, "AES-128-ECB", "");
        break;
    case NID_aes_192_ctr:
        keylen = 24;
        cipher = EVP_CIPHER_fetch(drbg->libctx, "AES-192-ECB", "");
        break;
    case NID_aes_256_ctr:
        keylen = 32;
        cipher = EVP_CIPHER_fetch(drbg->libctx, "AES-256-ECB", "");
        break;
    }
    if (cipher == NULL)
        return 0;

    EVP_CIPHER_free(ctr->cipher);
    ctr->cipher = cipher;

    drbg->meth = &drbg_ctr_meth;

    ctr->keylen = keylen;
    if (ctr->ctx == NULL)
        ctr->ctx = EVP_CIPHER_CTX_new();
    if (ctr->ctx == NULL)
        return 0;
    drbg->strength = keylen * 8;
    drbg->seedlen = keylen + 16;

    if (drbg->df) {
        /* df initialisation */
        static const unsigned char df_key[32] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };
        const EVP_CIPHER *cipher = ossl_prov_cipher_cipher(&ctr->cipher);

        if (ctr->ctx_df == NULL)
            ctr->ctx_df = EVP_CIPHER_CTX_new();
        if (ctr->ctx_df == NULL)
            return 0;
        /* Set key schedule for df_key */
        if (!EVP_CipherInit_ex(ctr->ctx_df, cipher, NULL, df_key, NULL, 1))
            return 0;

        drbg->min_entropylen = ctr->keylen;
        drbg->max_entropylen = DRBG_MAX_LENGTH;
        drbg->min_noncelen = drbg->min_entropylen / 2;
        drbg->max_noncelen = DRBG_MAX_LENGTH;
        drbg->max_perslen = DRBG_MAX_LENGTH;
        drbg->max_adinlen = DRBG_MAX_LENGTH;
    } else {
#ifdef FIPS_MODE
        ERR_raise(ERR_LIB_PROV, RAND_R_DERIVATION_FUNCTION_MANDATORY_FOR_FIPS);
        return 0;
#else
        drbg->min_entropylen = drbg->seedlen;
        drbg->max_entropylen = drbg->seedlen;
        /* Nonce not used */
        drbg->min_noncelen = 0;
        drbg->max_noncelen = 0;
        drbg->max_perslen = drbg->seedlen;
        drbg->max_adinlen = drbg->seedlen;
#endif
    }

    drbg->max_request = 1 << 16;
#endif
    return 1;
}

static void *drbg_ctr_new_wrapper(void *provctx, int secure, int df)
{
    return prov_rand_drbg_new(provctx, secure, df, &drbg_ctr_new);
}

static void drbg_ctr_free_wrapper(void *vdrbg)
{
    PROV_RAND *drbg = (PROV_RAND *)vdrbg;
    PROV_RAND_CTR *ctr = (PROV_RAND_CTR *)drbg->data;

    if (drbg->secure)
        OPENSSL_secure_clear_free(ctr, sizeof(*ctr));
    else
        OPENSSL_clear_free(ctr, sizeof(*ctr));
    prov_rand_free(drbg);
}

static int drbg_ctr_get_ctx_params(void *vdrbg, OSSL_PARAM params[])
{
    PROV_RAND *drbg = (PROV_RAND *)vdrbg;

    return drbg_get_ctx_params(drbg, params);
}

static const OSSL_PARAM *drbg_ctr_gettable_ctx_params(void)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_DRBG_GETABLE_CTX_COMMON,
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

static int drbg_ctr_set_ctx_params(void *vdrbg, const OSSL_PARAM params[])
{
    PROV_RAND *drbg = (PROV_RAND *)vdrbg;
    PROV_RAND_CTR *ctr = (PROV_RAND_CTR *)drbg->data;
    OPENSSL_CTX *provctx = PROV_LIBRARY_CONTEXT_OF(drbg->provctx);
    const EVP_CIPHER *cipher;
    char buf[100], *cp;
    OSSL_PARAM_BLD pb;
    const OSSL_PARAM *pp;
    int i;

    if ((pp = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_CIPHER))
        != NULL) {
        if ((cp = strrchr(pp->key, '_')) != NULL
                && strcasecmp(cp, "_ctr") == 0) {
            /* Need to convert _CTR cipher mode to _ECB */
            ossl_param_bld_init(&pb);
            for (i = 0; params[i].key != NULL; i++)
                if (pp != params + i
                        && !ossl_param_bld_push_param(&pb, params + i))
                    return 0;
            strncpy(buf, pp->key, sizeof(buf) - 1);
            buf[sizeof(buf) - 1] = '\0';
            cp = strrchr(buf, '_');
            strcpy(cp + 1, "ecb");
            if (!ossl_param_bld_push_utf8_string(&pb, OSSL_RAND_PARAM_CIPHER,
                                                 buf, 0))
                return 0;
            if ((pp = ossl_param_bld_to_param(&pb)) == NULL)
                return 0;
        } else {
            pp = params;
        }
        i = ossl_prov_cipher_load_from_params(&ctr->cipher, pp, provctx);
        if (pp != params)
            ossl_param_bld_free((OSSL_PARAM *)pp);
        if (!i)
            return 0;
        cipher = ossl_prov_cipher_cipher(&ctr->cipher);
        if (cipher != NULL) {
            OSSL_PARAM p2[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

            *p2 = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN,
                                              &ctr->keylen);
            if (!EVP_CIPHER_get_params((EVP_CIPHER *)cipher, p2))
                return 0;
            if (ctr->ctx == NULL)
                ctr->ctx = EVP_CIPHER_CTX_new();
            if (ctr->ctx == NULL)
                return 0;
            drbg->strength = ctr->keylen * 8;
            drbg->seedlen = ctr->keylen + 16;
            if (ctr->df) {
                /* df initialisation */
                static const unsigned char df_key[32] = {
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
                };

                if (ctr->ctx_df == NULL)
                    ctr->ctx_df = EVP_CIPHER_CTX_new();
                if (ctr->ctx_df == NULL)
                    return 0;
                /* Set key schedule for df_key */
                if (!EVP_CipherInit_ex(ctr->ctx_df, cipher, NULL, df_key,
                                       NULL, 1))
                    return 0;

                drbg->min_entropylen = ctr->keylen;
                drbg->min_noncelen = drbg->min_entropylen / 2;
            } else {
                drbg->min_entropylen = drbg->seedlen;
                drbg->max_entropylen = drbg->seedlen;
                drbg->max_perslen = drbg->seedlen;
                drbg->max_adinlen = drbg->seedlen;
            }
        }
    }
    return drbg_set_ctx_params(drbg, params);
}

static const OSSL_PARAM *drbg_ctr_settable_ctx_params(void)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_RAND_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_RAND_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_DRBG_SETABLE_CTX_COMMON,
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

const OSSL_DISPATCH drbg_ctr_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void(*)(void))drbg_ctr_new_wrapper },
    { OSSL_FUNC_RAND_FREECTX, (void(*)(void))drbg_ctr_free_wrapper },
    { OSSL_FUNC_RAND_INSTANTIATE, (void(*)(void))drbg_ctr_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void(*)(void))drbg_ctr_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void(*)(void))drbg_ctr_generate },
    { OSSL_FUNC_RAND_RESEED, (void(*)(void))drbg_ctr_reseed },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS,
      (void(*)(void))drbg_ctr_settable_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void(*)(void))drbg_ctr_set_ctx_params },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
      (void(*)(void))drbg_ctr_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void(*)(void))drbg_ctr_get_ctx_params },
    { 0, NULL }
};
