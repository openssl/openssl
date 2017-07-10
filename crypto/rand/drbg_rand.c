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
#include "rand_drbg_lcl.h"
#include "internal/thread_once.h"

/*
 * Mapping of SP800-90 DRBGs to OpenSSL RAND_METHOD
 */


/*
 * Since we only have one global PRNG used at any time in OpenSSL use a global
 * variable to store context.
 */
static DRBG_CTX ossl_drbg;

static CRYPTO_RWLOCK *ossl_drbg_lock = NULL;
static CRYPTO_ONCE ossl_drbg_init = CRYPTO_ONCE_STATIC_INIT;

DEFINE_RUN_ONCE_STATIC(do_ossl_drbg_init)
{
    ossl_drbg_lock = CRYPTO_THREAD_lock_new();
    return ossl_drbg_lock != NULL;
}

void rand_drbg_cleanup(void)
{
    CRYPTO_THREAD_lock_free(ossl_drbg_lock);
}

static void inc_128(DRBG_CTR_CTX *cctx)
{
    int i;
    unsigned char c;
    unsigned char *p = cctx->V + 15;

    for (i = 0; i < 16; i++, p--) {
        c = *p;
        c++;
        *p = c;
        if (c)
            return;
    }
}

static void ctr_XOR(DRBG_CTR_CTX *cctx, const unsigned char *in, size_t inlen)
{
    size_t i, n;

    /*
     * Any zero padding will have no effect on the result as we
     * are XORing. So just process however much input we have.
     */

    if (inlen < cctx->keylen)
        n = inlen;
    else
        n = cctx->keylen;

    for (i = 0; i < n; i++)
        cctx->K[i] ^= in[i];
    if (inlen <= cctx->keylen)
        return;

    n = inlen - cctx->keylen;
    if (n > 16) {
        /* Should never happen */
        n = 16;
    }
    for (i = 0; i < 16; i++)
        cctx->V[i] ^= in[i + cctx->keylen];
}

/*
 * Process a complete block using BCC algorithm of SPP 800-90 10.4.3
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
 * see 10.4.2 stage 7.
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
    size_t inlen;
    unsigned char *p = cctx->bltmp;
    static unsigned char c80 = 0x80;

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
 * NB the no-df Update in SP800-90 specifies a constant input length
 * of seedlen, however other uses of this algorithm pad the input with
 * zeroes if necessary and have up to two parameters XORed together,
 * handle both cases in this function instead.
 */
static void ctr_update(DRBG_CTX *dctx,
                       const unsigned char *in1, size_t in1len,
                       const unsigned char *in2, size_t in2len,
                       const unsigned char *nonce, size_t noncelen)
{
    DRBG_CTR_CTX *cctx = &dctx->d.ctr;

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

    if (dctx->xflags & RAND_DRBG_FLAG_CTR_USE_DF) {
        /* If no input reuse existing derived value */
        if (in1 || nonce || in2)
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

static int drbg_ctr_instantiate(DRBG_CTX *dctx,
                                const unsigned char *ent, size_t entlen,
                                const unsigned char *nonce, size_t noncelen,
                                const unsigned char *pers, size_t perslen)
{
    DRBG_CTR_CTX *cctx = &dctx->d.ctr;

    memset(cctx->K, 0, sizeof(cctx->K));
    memset(cctx->V, 0, sizeof(cctx->V));
    AES_set_encrypt_key(cctx->K, dctx->strength, &cctx->ks);
    ctr_update(dctx, ent, entlen, pers, perslen, nonce, noncelen);
    return 1;
}

static int drbg_ctr_reseed(DRBG_CTX *dctx, 
                           const unsigned char *ent, size_t entlen,
                           const unsigned char *adin, size_t adinlen)
{
    ctr_update(dctx, ent, entlen, adin, adinlen, NULL, 0);
    return 1;
}

static int drbg_ctr_generate(DRBG_CTX *dctx,
                             unsigned char *out, size_t outlen,
                             const unsigned char *adin, size_t adinlen)
{
    DRBG_CTR_CTX *cctx = &dctx->d.ctr;

    if (adin != NULL && adinlen) {
        ctr_update(dctx, adin, adinlen, NULL, 0, NULL, 0);
        /* This means we reuse derived value */
        if (dctx->xflags & RAND_DRBG_FLAG_CTR_USE_DF) {
            adin = NULL;
            adinlen = 1;
        }
    } else {
        adinlen = 0;
    }

    for ( ; ; ) {
        inc_128(cctx);
        if (!dctx->lb_valid) {
            AES_encrypt(cctx->V, dctx->lb, &cctx->ks);
            dctx->lb_valid = 1;
            continue;
        }
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

static int drbg_ctr_uninstantiate(DRBG_CTX *dctx)
{
    memset(&dctx->d.ctr, 0, sizeof(dctx->d.ctr));
    return 1;
}

int drbg_ctr_init(DRBG_CTX *dctx)
{
    DRBG_CTR_CTX *cctx = &dctx->d.ctr;
    size_t keylen;

    switch (dctx->type) {
    default:
        return -2;
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

    dctx->instantiate = drbg_ctr_instantiate;
    dctx->reseed = drbg_ctr_reseed;
    dctx->generate = drbg_ctr_generate;
    dctx->uninstantiate = drbg_ctr_uninstantiate;
    cctx->keylen = keylen;
    dctx->strength = keylen * 8;
    dctx->blocklength = 16;
    dctx->seedlen = keylen + 16;

    if (dctx->xflags & RAND_DRBG_FLAG_CTR_USE_DF) {
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
    dctx->reseed_interval = 1 << 24;
    return 1;
}


/*
 * This is Hash_df from SP 800-90 10.4.1
 */

static int hash_df(DRBG_CTX *dctx, unsigned char *out,
                   const unsigned char *in1, size_t in1len,
                   const unsigned char *in2, size_t in2len,
                   const unsigned char *in3, size_t in3len,
                   const unsigned char *in4, size_t in4len)
{
    EVP_MD_CTX *mctx = dctx->d.hash.mctx;
    unsigned char *vtmp = dctx->d.hash.vtmp;
    unsigned char tmp[6];
    /*
     * Standard only ever needs seedlen bytes which is always less than
     * maximum permitted so no need to check length.
     */
    size_t outlen = dctx->seedlen;

    tmp[0] = 1;
    tmp[1] = ((outlen * 8) >> 24) & 0xff;
    tmp[2] = ((outlen * 8) >> 16) & 0xff;
    tmp[3] = ((outlen * 8) >> 8) & 0xff;
    tmp[4] = (outlen * 8) & 0xff;
    if (in1 == NULL) {
        tmp[5] = (unsigned char)in1len;
        in1 = tmp + 5;
        in1len = 1;
    }

    for ( ; ; ) {
        if (!EVP_DigestInit(mctx, dctx->d.hash.md))
            return 0;
        if (!EVP_DigestUpdate(mctx, tmp, 5)
                || (in1 != NULL && !EVP_DigestUpdate(mctx, in1, in1len))
                || (in2 != NULL && !EVP_DigestUpdate(mctx, in2, in2len))
                || (in3 != NULL && !EVP_DigestUpdate(mctx, in3, in3len))
                || (in4 != NULL && !EVP_DigestUpdate(mctx, in4, in4len)))
            return 0;

        if (outlen < dctx->blocklength) {
            if (!EVP_DigestFinal(mctx, vtmp, NULL))
                return 0;
            memcpy(out, vtmp, outlen);
            OPENSSL_cleanse(vtmp, dctx->blocklength);
            return 1;
        } else if (!EVP_DigestFinal(mctx, out, NULL))
            return 0;

        outlen -= dctx->blocklength;
        if (outlen == 0)
            return 1;
        tmp[0]++;
        out += dctx->blocklength;
    }
}


/*
 * Add an unsigned buffer to the buf value, storing the result in buf. For
 * this algorithm the length of input never exceeds the seed length.
 */
static void ctx_add_buf(DRBG_CTX *dctx, unsigned char *buf,
                        unsigned char *in, size_t inlen)
{
    size_t i = inlen;
    const unsigned char *q;
    unsigned char c, *p;

    p = buf + dctx->seedlen;
    q = in + inlen;

    OPENSSL_assert(i <= dctx->seedlen);

    /* Special case: zero length, just increment buffer */
    c = i ? 0 : 1;

    while (i) {
        int r;

        p--;
        q--;
        r = *p + *q + c;
        /* Carry */
        if (r > 0xff)
            c = 1;
        else
            c = 0;
        *p = r & 0xff;
        i--;
    }

    i = dctx->seedlen - inlen;

    /* If not adding whole buffer handle final carries */
    if (c && i) {
        do {
            p--;
            c = *p;
            c++;
            *p = c;
            if (c)
                return;
        } while (i--);
    }
}

/*
 * Finalise and add hash to V
 */
static int ctx_add_md(DRBG_CTX *dctx)
{
    if (!EVP_DigestFinal(dctx->d.hash.mctx, dctx->d.hash.vtmp, NULL))
        return 0;
    ctx_add_buf(dctx, dctx->d.hash.V, dctx->d.hash.vtmp, dctx->blocklength);
    return 1;
}

static int hash_gen(DRBG_CTX *dctx, unsigned char *out, size_t outlen)
{
    DRBG_HASH_CTX *hctx = &dctx->d.hash;

    if (outlen == 0)
        return 1;
    memcpy(hctx->vtmp, hctx->V, dctx->seedlen);

    for( ; ; ) {
        if (!EVP_DigestInit(hctx->mctx, hctx->md)
                || !EVP_DigestUpdate(hctx->mctx, hctx->vtmp, dctx->seedlen))
            return 0;
        if (!dctx->lb_valid) {
            if (EVP_DigestFinal(hctx->mctx, dctx->lb, NULL))
                dctx->lb_valid = 1;
        } else if (outlen < dctx->blocklength) {
            if (!EVP_DigestFinal(hctx->mctx, hctx->vtmp, NULL))
                return 0;
            memcpy(out, hctx->vtmp, outlen);
            return 1;
        } else {
            if (EVP_DigestFinal(hctx->mctx, out, NULL))
                return 0;
            outlen -= dctx->blocklength;
            if (outlen == 0)
                return 1;
            out += dctx->blocklength;
        }
        ctx_add_buf(dctx, hctx->vtmp, NULL, 0);
    }
}

static int drbg_hash_instantiate(DRBG_CTX *dctx,
                                 const unsigned char *ent, size_t ent_len,
                                 const unsigned char *nonce, size_t nonce_len,
                                 const unsigned char *pstr, size_t pstr_len)
{
    DRBG_HASH_CTX *hctx = &dctx->d.hash;

    if (!hash_df(dctx, hctx->V, 
                 ent, ent_len, nonce, nonce_len, pstr, pstr_len,
                 NULL, 0))
        return 0;
    if (!hash_df(dctx, hctx->C, 
                 NULL, 0, hctx->V, dctx->seedlen, NULL, 0,
                 NULL, 0))
        return 0;

    return 1;
}


static int drbg_hash_reseed(DRBG_CTX *dctx,
                            const unsigned char *ent, size_t ent_len,
                            const unsigned char *adin, size_t adin_len)
{
    DRBG_HASH_CTX *hctx = &dctx->d.hash;

    /* V about to be updated so use C as output instead */
    if (!hash_df(dctx, hctx->C,
                 NULL, 1, hctx->V, dctx->seedlen, ent, ent_len,
                 adin, adin_len))
        return 0;
    memcpy(hctx->V, hctx->C, dctx->seedlen);
    if (!hash_df(dctx, hctx->C,
                 NULL, 0, hctx->V, dctx->seedlen, NULL, 0,
                 NULL, 0))
        return 0;
    return 1;
}

static int drbg_hash_generate(DRBG_CTX *dctx,
                              unsigned char *out, size_t outlen,
                              const unsigned char *adin, size_t adin_len)
{
    DRBG_HASH_CTX *hctx = &dctx->d.hash;
    EVP_MD_CTX *mctx = hctx->mctx;
    unsigned char tmp[4];

    if (adin != NULL && adin_len) {
        tmp[0] = 2;
        if (!EVP_DigestInit(mctx, hctx->md)
                || !EVP_DigestUpdate(mctx, tmp, 1)
                || !EVP_DigestUpdate(mctx, hctx->V, dctx->seedlen)
                || !EVP_DigestUpdate(mctx, adin, adin_len)
                || !ctx_add_md(dctx))
            return 0;
    }
    if (!hash_gen(dctx, out, outlen))
        return 0;

    tmp[0] = 3;
    if (!EVP_DigestInit(mctx, hctx->md)
            || !EVP_DigestUpdate(mctx, tmp, 1)
            || !EVP_DigestUpdate(mctx, hctx->V, dctx->seedlen)
            || !ctx_add_md(dctx))
        return 0;

    ctx_add_buf(dctx, hctx->V, hctx->C, dctx->seedlen);
    tmp[0] = (dctx->reseed_counter >> 24) & 0xff;
    tmp[1] = (dctx->reseed_counter >> 16) & 0xff;
    tmp[2] = (dctx->reseed_counter >> 8) & 0xff;
    tmp[3] = dctx->reseed_counter & 0xff;
    ctx_add_buf(dctx, hctx->V, tmp, 4);
    return 1;
}

static int drbg_hash_uninstantiate(DRBG_CTX *dctx)
{
    EVP_MD_CTX_free(dctx->d.hash.mctx);
    OPENSSL_cleanse(&dctx->d.hash, sizeof(dctx->d.hash));
    return 1;
}

int drbg_hash_init(DRBG_CTX *dctx)
{
    const EVP_MD *md = EVP_get_digestbynid(dctx->type);
    DRBG_HASH_CTX *hctx = &dctx->d.hash;

    if (md == NULL)
        return -2;
    switch (dctx->type) {
    default:
        dctx->strength = 256;
        break;
    case NID_sha224:
        dctx->strength = 192;
        break;
    }

    dctx->instantiate = drbg_hash_instantiate;
    dctx->reseed = drbg_hash_reseed;
    dctx->generate = drbg_hash_generate;
    dctx->uninstantiate = drbg_hash_uninstantiate;
    dctx->d.hash.md = md;
    hctx->mctx = EVP_MD_CTX_new();

    /* These are taken from SP 800-90 10.1 table 2 */
    dctx->blocklength = EVP_MD_size(md);
    if (dctx->blocklength > 32)
        dctx->seedlen = 111;
    else
        dctx->seedlen = 55;

    dctx->min_entropy = dctx->strength / 8;
    dctx->max_entropy = DRBG_MAX_LENGTH;
    dctx->min_nonce = dctx->min_entropy / 2;
    dctx->max_nonce = DRBG_MAX_LENGTH;
    dctx->max_pers = DRBG_MAX_LENGTH;
    dctx->max_adin = DRBG_MAX_LENGTH;
    dctx->max_request = 1 << 16;
    dctx->reseed_interval = 1 << 24;
    return 1;
}

/*
 * This is HMAC from SP 800-90
 */

static int drbg_hmac_update(DRBG_CTX *dctx,
                            const unsigned char *in1, size_t in1len,
                            const unsigned char *in2, size_t in2len,
                            const unsigned char *in3, size_t in3len)
{
    static unsigned char c0 = 0, c1 = 1;
    DRBG_HMAC_CTX *hmac = &dctx->d.hmac;
    HMAC_CTX *hctx = hmac->hctx;

    if (!HMAC_Init_ex(hctx, hmac->K, dctx->blocklength, hmac->md, NULL)
            || !HMAC_Update(hctx, hmac->V, dctx->blocklength)
            || !HMAC_Update(hctx, &c0, 1)
            || (in1len && !HMAC_Update(hctx, in1, in1len))
            || (in2len && !HMAC_Update(hctx, in2, in2len))
            || (in3len && !HMAC_Update(hctx, in3, in3len))
            || !HMAC_Final(hctx, hmac->K, NULL)
            || !HMAC_Init_ex(hctx, hmac->K, dctx->blocklength, hmac->md, NULL)
            || !HMAC_Update(hctx, hmac->V, dctx->blocklength)
            || !HMAC_Final(hctx, hmac->V, NULL))
        return 0;

    if (in1len == 0 && in2len == 0 && in3len == 0)
        return 1;

    if (!HMAC_Init_ex(hctx, hmac->K, dctx->blocklength, hmac->md, NULL)
            || !HMAC_Update(hctx, hmac->V, dctx->blocklength)
            || !HMAC_Update(hctx, &c1, 1)
            || (in1len && !HMAC_Update(hctx, in1, in1len))
            || (in2len && !HMAC_Update(hctx, in2, in2len))
            || (in3len && !HMAC_Update(hctx, in3, in3len))
            || !HMAC_Final(hctx, hmac->K, NULL)
            || !HMAC_Init_ex(hctx, hmac->K, dctx->blocklength, hmac->md, NULL)
            || !HMAC_Update(hctx, hmac->V, dctx->blocklength)
            || !HMAC_Final(hctx, hmac->V, NULL))
        return 0;

    return 1;
}

static int drbg_hmac_instantiate(DRBG_CTX *dctx,
                                 const unsigned char *ent, size_t ent_len,
                                 const unsigned char *nonce, size_t nonce_len,
                                 const unsigned char *pstr, size_t pstr_len)
{
    DRBG_HMAC_CTX *hmac = &dctx->d.hmac;

    memset(hmac->K, 0, dctx->blocklength);
    memset(hmac->V, 1, dctx->blocklength);
    if (!drbg_hmac_update(dctx,
                ent, ent_len, nonce, nonce_len, pstr, pstr_len))
        return 0;
    return 1;
}

static int drbg_hmac_reseed(DRBG_CTX *dctx,
                            const unsigned char *ent, size_t ent_len,
                            const unsigned char *adin, size_t adin_len)
{
    if (!drbg_hmac_update(dctx,
                ent, ent_len, adin, adin_len, NULL, 0))
        return 0;
    return 1;
}

static int drbg_hmac_generate(DRBG_CTX *dctx,
                              unsigned char *out, size_t outlen,
                              const unsigned char *adin, size_t adin_len)
{
    DRBG_HMAC_CTX *hmac = &dctx->d.hmac;
    HMAC_CTX *hctx = hmac->hctx;
    const unsigned char *Vtmp = hmac->V;

    if (adin_len
            && !drbg_hmac_update(dctx, adin, adin_len, NULL, 0, NULL, 0))
        return 0;
    for ( ; ; ) {
        if (!HMAC_Init_ex(hctx, hmac->K, dctx->blocklength, hmac->md, NULL)
                || !HMAC_Update(hctx, Vtmp, dctx->blocklength))
            return 0;
        if (!dctx->lb_valid) {
            if (!HMAC_Final(hctx, dctx->lb, NULL))
                return 0;
            dctx->lb_valid = 1;
            Vtmp = dctx->lb;
            continue;
        }
        if (outlen > dctx->blocklength) {
            if (!HMAC_Final(hctx, out, NULL))
                return 0;
            Vtmp = out;
        } else {
            if (!HMAC_Final(hctx, hmac->V, NULL))
                return 0;
            memcpy(out, hmac->V, outlen);
            break;
        }
        out += dctx->blocklength;
        outlen -= dctx->blocklength;
    }
    if (!drbg_hmac_update(dctx, adin, adin_len, NULL, 0, NULL, 0))
        return 0;
    return 1;
}

static int drbg_hmac_uninstantiate(DRBG_CTX *dctx)
{
    HMAC_CTX_free(dctx->d.hmac.hctx);
    OPENSSL_cleanse(&dctx->d.hmac, sizeof(dctx->d.hmac));
    return 1;
}

int drbg_hmac_init(DRBG_CTX *dctx)
{
    const EVP_MD *md = NULL;
    DRBG_HMAC_CTX *hctx = &dctx->d.hmac;

    dctx->strength = 256;
    switch (dctx->type) {
    default:
        dctx->strength = 0;
        return -2;
    case NID_hmacWithSHA1:
        md = EVP_sha1();
        dctx->strength = 128;
        break;
    case NID_hmacWithSHA224:
        md = EVP_sha224();
        dctx->strength = 192;
        break;
    case NID_hmacWithSHA256:
        md = EVP_sha256();
        break;
    case NID_hmacWithSHA384:
        md = EVP_sha384();
        break;
    case NID_hmacWithSHA512:
        md = EVP_sha512();
        break;
    }

    dctx->instantiate = drbg_hmac_instantiate;
    dctx->reseed = drbg_hmac_reseed;
    dctx->generate = drbg_hmac_generate;
    dctx->uninstantiate = drbg_hmac_uninstantiate;
    hctx->hctx = HMAC_CTX_new();
    hctx->md = md;
    dctx->blocklength = EVP_MD_size(md);
    dctx->seedlen = EVP_MD_size(md);
    dctx->min_entropy = dctx->strength / 8;
    dctx->max_entropy = DRBG_MAX_LENGTH;
    dctx->min_nonce = dctx->min_entropy / 2;
    dctx->max_nonce = DRBG_MAX_LENGTH;
    dctx->max_pers = DRBG_MAX_LENGTH;
    dctx->max_adin = DRBG_MAX_LENGTH;
    dctx->max_request = 1 << 16;
    dctx->reseed_interval = 1 << 24;
    return 1;
}

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
    unsigned char *adin = NULL;
    size_t adinlen = 0;

    CRYPTO_THREAD_write_lock(ossl_drbg_lock);
    do {
        size_t rcnt;

        if (count > (int)dctx->max_request)
            rcnt = dctx->max_request;
        else
            rcnt = count;
        if (dctx->get_adin) {
            adinlen = dctx->get_adin(dctx, &adin);
            if (adinlen && !adin) {
                RANDerr(RAND_F_DRBG_BYTES, RAND_R_ERROR_RETRIEVING_ADDITIONAL_INPUT);
                goto err;
            }
        }
        ret = RAND_DRBG_generate(dctx, out, rcnt, 0, adin, adinlen);
        if (adin) {
            if (dctx->cleanup_adin)
                dctx->cleanup_adin(dctx, adin, adinlen);
            adin = NULL;
        }
        if (!ret)
            goto err;
        out += rcnt;
        count -= rcnt;
    } while (count);
    ret = 1;
err:
    CRYPTO_THREAD_unlock(ossl_drbg_lock);
    return ret;
}

static int drbg_status(void)
{
    DRBG_CTX *dctx = RAND_DRBG_get_default();
    int ret;

    CRYPTO_THREAD_write_lock(ossl_drbg_lock);
    ret = dctx->status == DRBG_STATUS_READY ? 1 : 0;
    CRYPTO_THREAD_unlock(ossl_drbg_lock);
    return ret;
}

static void drbg_cleanup(void)
{
    DRBG_CTX *dctx = RAND_DRBG_get_default();

    CRYPTO_THREAD_write_lock(ossl_drbg_lock);
    RAND_DRBG_uninstantiate(dctx);
    CRYPTO_THREAD_unlock(ossl_drbg_lock);
}

static int drbg_seed(const void *seed, int seedlen)
{
    DRBG_CTX *dctx = RAND_DRBG_get_default();

    if (dctx->rand_seed_cb)
        return dctx->rand_seed_cb(dctx, seed, seedlen);
    return 1;
}

static int drbg_add(const void *seed, int seedlen,
        double add_entropy)
{
    DRBG_CTX *dctx = RAND_DRBG_get_default();

    if (dctx->rand_add_cb)
        return dctx->rand_add_cb(dctx, seed, seedlen, add_entropy);
    return 1;
}

static const RAND_METHOD rand_drbg_meth =
{
    drbg_seed,
    drbg_bytes,
    drbg_cleanup,
    drbg_add,
    drbg_bytes,
    drbg_status
};

const RAND_METHOD *RAND_drbg(void)
{
    return &rand_drbg_meth;
}

