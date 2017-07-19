/*
 * Copyright 2011-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "rand_lcl.h"
#include "internal/thread_once.h"

/*
 * Mapping of NIST SP 800-90A DRBG to OpenSSL RAND_METHOD.
 */


/*
 * The default global DRBG and its auto-init/auto-cleanup.
 */
static DRBG_CTX ossl_drbg;

static CRYPTO_ONCE ossl_drbg_init = CRYPTO_ONCE_STATIC_INIT;

DEFINE_RUN_ONCE_STATIC(do_ossl_drbg_init)
{
    ossl_drbg.lock = CRYPTO_THREAD_lock_new();
    return ossl_drbg.lock != NULL;
}

void rand_drbg_cleanup(void)
{
    CRYPTO_THREAD_lock_free(ossl_drbg.lock);
}

static void inc_128(DRBG_CTR_CTX *cctx)
{
    int i;
    unsigned char c;
    unsigned char *p = &cctx->V[15];

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

static void ctr_XOR(DRBG_CTR_CTX *cctx, const unsigned char *in, size_t inlen)
{
    size_t i, n;

    if (in == NULL || inlen == 0)
        return;

    /*
     * Any zero padding will have no effect on the result as we
     * are XORing. So just process however much input we have.
     */
    n = inlen < cctx->keylen ? inlen : cctx->keylen;
    for (i = 0; i < n; i++)
        cctx->K[i] ^= in[i];
    if (inlen <= cctx->keylen)
        return;

    n = inlen - cctx->keylen;
    if (n > 16) {
        /* Should never happen */
        n = 16;
    }
    for (i = 0; i < n; i++)
        cctx->V[i] ^= in[i + cctx->keylen];
}

/*
 * Process a complete block using BCC algorithm of SP 800-90A 10.3.3
 */
static void ctr_BCC_block(DRBG_CTR_CTX *cctx, unsigned char *out,
                          const unsigned char *in)
{
    int i;

    for (i = 0; i < 16; i++)
        out[i] ^= in[i];
    AES_encrypt(out, out, &cctx->df_ks);
}


/*
 * Handle several BCC operations for as much data as we need for K and X
 */
static void ctr_BCC_blocks(DRBG_CTR_CTX *cctx, const unsigned char *in)
{
    ctr_BCC_block(cctx, cctx->KX, in);
    ctr_BCC_block(cctx, cctx->KX + 16, in);
    if (cctx->keylen != 16)
        ctr_BCC_block(cctx, cctx->KX + 32, in);
}

/*
 * Initialise BCC blocks: these have the value 0,1,2 in leftmost positions:
 * see 10.3.1 stage 7.
 */
static void ctr_BCC_init(DRBG_CTR_CTX *cctx)
{
    memset(cctx->KX, 0, 48);
    memset(cctx->bltmp, 0, 16);
    ctr_BCC_block(cctx, cctx->KX, cctx->bltmp);
    cctx->bltmp[3] = 1;
    ctr_BCC_block(cctx, cctx->KX + 16, cctx->bltmp);
    if (cctx->keylen != 16) {
        cctx->bltmp[3] = 2;
        ctr_BCC_block(cctx, cctx->KX + 32, cctx->bltmp);
    }
}

/*
 * Process several blocks into BCC algorithm, some possibly partial
 */
static void ctr_BCC_update(DRBG_CTR_CTX *cctx,
                           const unsigned char *in, size_t inlen)
{
    if (in == NULL || inlen == 0)
        return;

    /* If we have partial block handle it first */
    if (cctx->bltmp_pos) {
        size_t left = 16 - cctx->bltmp_pos;

        /* If we now have a complete block process it */
        if (inlen >= left) {
            memcpy(cctx->bltmp + cctx->bltmp_pos, in, left);
            ctr_BCC_blocks(cctx, cctx->bltmp);
            cctx->bltmp_pos = 0;
            inlen -= left;
            in += left;
        }
    }

    /* Process zero or more complete blocks */
    for (; inlen >= 16; in += 16, inlen -= 16) {
        ctr_BCC_blocks(cctx, in);
    }

    /* Copy any remaining partial block to the temporary buffer */
    if (inlen > 0) {
        memcpy(cctx->bltmp + cctx->bltmp_pos, in, inlen);
        cctx->bltmp_pos += inlen;
    }
}

static void ctr_BCC_final(DRBG_CTR_CTX *cctx)
{
    if (cctx->bltmp_pos) {
        memset(cctx->bltmp + cctx->bltmp_pos, 0, 16 - cctx->bltmp_pos);
        ctr_BCC_blocks(cctx, cctx->bltmp);
    }
}

static void ctr_df(DRBG_CTR_CTX *cctx,
                   const unsigned char *in1, size_t in1len,
                   const unsigned char *in2, size_t in2len,
                   const unsigned char *in3, size_t in3len)
{
    static unsigned char c80 = 0x80;
    size_t inlen;
    unsigned char *p = cctx->bltmp;

    ctr_BCC_init(cctx);
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
    *p = (unsigned char)((cctx->keylen + 16) & 0xff);
    cctx->bltmp_pos = 8;
    ctr_BCC_update(cctx, in1, in1len);
    ctr_BCC_update(cctx, in2, in2len);
    ctr_BCC_update(cctx, in3, in3len);
    ctr_BCC_update(cctx, &c80, 1);
    ctr_BCC_final(cctx);
    /* Set up key K */
    AES_set_encrypt_key(cctx->KX, cctx->keylen * 8, &cctx->df_kxks);
    /* X follows key K */
    AES_encrypt(cctx->KX + cctx->keylen, cctx->KX, &cctx->df_kxks);
    AES_encrypt(cctx->KX, cctx->KX + 16, &cctx->df_kxks);
    if (cctx->keylen != 16)
        AES_encrypt(cctx->KX + 16, cctx->KX + 32, &cctx->df_kxks);
}

/*
 * NB the no-df Update in SP800-90A specifies a constant input length
 * of seedlen, however other uses of this algorithm pad the input with
 * zeroes if necessary and have up to two parameters XORed together,
 * handle both cases in this function instead.
 */
static void ctr_update(DRBG_CTX *dctx,
                       const unsigned char *in1, size_t in1len,
                       const unsigned char *in2, size_t in2len,
                       const unsigned char *nonce, size_t noncelen)
{
    DRBG_CTR_CTX *cctx = &dctx->ctr;

    /* ks is already setup for correct key */
    inc_128(cctx);
    AES_encrypt(cctx->V, cctx->K, &cctx->ks);

    /* If keylen longer than 128 bits need extra encrypt */
    if (cctx->keylen != 16) {
        inc_128(cctx);
        AES_encrypt(cctx->V, cctx->K + 16, &cctx->ks);
    }
    inc_128(cctx);
    AES_encrypt(cctx->V, cctx->V, &cctx->ks);

    /* If 192 bit key part of V is on end of K */
    if (cctx->keylen == 24) {
        memcpy(cctx->V + 8, cctx->V, 8);
        memcpy(cctx->V, cctx->K + 24, 8);
    }

    if (dctx->flags & RAND_DRBG_FLAG_CTR_USE_DF) {
        /* If no input reuse existing derived value */
        if (in1 != NULL || nonce != NULL || in2 != NULL)
            ctr_df(cctx, in1, in1len, nonce, noncelen, in2, in2len);
        /* If this a reuse input in1len != 0 */
        if (in1len)
            ctr_XOR(cctx, cctx->KX, dctx->seedlen);
    } else {
        ctr_XOR(cctx, in1, in1len);
        ctr_XOR(cctx, in2, in2len);
    }

    AES_set_encrypt_key(cctx->K, dctx->strength, &cctx->ks);
}

int ctr_instantiate(DRBG_CTX *dctx,
                    const unsigned char *ent, size_t entlen,
                    const unsigned char *nonce, size_t noncelen,
                    const unsigned char *pers, size_t perslen)
{
    DRBG_CTR_CTX *cctx = &dctx->ctr;

    memset(cctx->K, 0, sizeof(cctx->K));
    memset(cctx->V, 0, sizeof(cctx->V));
    AES_set_encrypt_key(cctx->K, dctx->strength, &cctx->ks);
    ctr_update(dctx, ent, entlen, pers, perslen, nonce, noncelen);
    return 1;
}

int ctr_reseed(DRBG_CTX *dctx,
               const unsigned char *ent, size_t entlen,
               const unsigned char *adin, size_t adinlen)
{
    ctr_update(dctx, ent, entlen, adin, adinlen, NULL, 0);
    return 1;
}

int ctr_generate(DRBG_CTX *dctx,
                 unsigned char *out, size_t outlen,
                 const unsigned char *adin, size_t adinlen)
{
    DRBG_CTR_CTX *cctx = &dctx->ctr;

    if (adin != NULL && adinlen != 0) {
        ctr_update(dctx, adin, adinlen, NULL, 0, NULL, 0);
        /* This means we reuse derived value */
        if (dctx->flags & RAND_DRBG_FLAG_CTR_USE_DF) {
            adin = NULL;
            adinlen = 1;
        }
    } else {
        adinlen = 0;
    }

    for ( ; ; ) {
        inc_128(cctx);
        if (outlen < 16) {
            /* Use K as temp space as it will be updated */
            AES_encrypt(cctx->V, cctx->K, &cctx->ks);
            memcpy(out, cctx->K, outlen);
            break;
        }
        AES_encrypt(cctx->V, out, &cctx->ks);
        out += 16;
        outlen -= 16;
        if (outlen == 0)
            break;
    }

    ctr_update(dctx, adin, adinlen, NULL, 0, NULL, 0);
    return 1;
}

int ctr_uninstantiate(DRBG_CTX *dctx)
{
    memset(&dctx->ctr, 0, sizeof(dctx->ctr));
    return 1;
}

int ctr_init(DRBG_CTX *dctx)
{
    DRBG_CTR_CTX *cctx = &dctx->ctr;
    size_t keylen;

    switch (dctx->nid) {
    default:
        /* This can't happen, but silence the compiler warning. */
        return -1;
    case NID_aes_128_ctr:
        keylen = 16;
        break;
    case NID_aes_192_ctr:
        keylen = 24;
        break;
    case NID_aes_256_ctr:
        keylen = 32;
        break;
    }

    cctx->keylen = keylen;
    dctx->strength = keylen * 8;
    dctx->blocklength = 16;
    dctx->seedlen = keylen + 16;

    if (dctx->flags & RAND_DRBG_FLAG_CTR_USE_DF) {
        /* df initialisation */
        static unsigned char df_key[32] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
        };
        /* Set key schedule for df_key */
        AES_set_encrypt_key(df_key, dctx->strength, &cctx->df_ks);

        dctx->min_entropy = cctx->keylen;
        dctx->max_entropy = DRBG_MAX_LENGTH;
        dctx->min_nonce = dctx->min_entropy / 2;
        dctx->max_nonce = DRBG_MAX_LENGTH;
        dctx->max_pers = DRBG_MAX_LENGTH;
        dctx->max_adin = DRBG_MAX_LENGTH;
    } else {
        dctx->min_entropy = dctx->seedlen;
        dctx->max_entropy = dctx->seedlen;
        /* Nonce not used */
        dctx->min_nonce = 0;
        dctx->max_nonce = 0;
        dctx->max_pers = dctx->seedlen;
        dctx->max_adin = dctx->seedlen;
    }

    dctx->max_request = 1 << 16;
    dctx->reseed_interval = MAX_RESEED;
    return 1;
}


/*
 * The following function tie the DRBG code into the RAND_METHOD
 */

DRBG_CTX *RAND_DRBG_get_default(void)
{
    if (!RUN_ONCE(&ossl_drbg_init, do_ossl_drbg_init))
        return NULL;
    return &ossl_drbg;
}

static int drbg_bytes(unsigned char *out, int count)
{
    DRBG_CTX *dctx = RAND_DRBG_get_default();
    int ret = 0;

    CRYPTO_THREAD_write_lock(dctx->lock);
    do {
        size_t rcnt;

        if (count > (int)dctx->max_request)
            rcnt = dctx->max_request;
        else
            rcnt = count;
        ret = RAND_DRBG_generate(dctx, out, rcnt, 0, NULL, 0);
        if (!ret)
            goto err;
        out += rcnt;
        count -= rcnt;
    } while (count);
    ret = 1;
err:
    CRYPTO_THREAD_unlock(dctx->lock);
    return ret;
}

static int drbg_status(void)
{
    DRBG_CTX *dctx = RAND_DRBG_get_default();
    int ret;

    CRYPTO_THREAD_write_lock(dctx->lock);
    ret = dctx->status == DRBG_STATUS_READY ? 1 : 0;
    CRYPTO_THREAD_unlock(dctx->lock);
    return ret;
}

static void drbg_cleanup(void)
{
    DRBG_CTX *dctx = RAND_DRBG_get_default();

    CRYPTO_THREAD_write_lock(dctx->lock);
    RAND_DRBG_uninstantiate(dctx);
    CRYPTO_THREAD_unlock(dctx->lock);
}

static const RAND_METHOD rand_drbg_meth =
{
    NULL,
    drbg_bytes,
    drbg_cleanup,
    NULL,
    drbg_bytes,
    drbg_status
};

const RAND_METHOD *RAND_drbg(void)
{
    return &rand_drbg_meth;
}
