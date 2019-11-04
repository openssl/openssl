/*
 * Copyright 2011-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "internal/thread_once.h"
#include "prov/providercommon.h"
#include "rand_local.h"

/* 440 bits from SP800-90Ar1 10.1 table 2 */
#define HASH_PRNG_SMALL_SEEDLEN   (440/8)
/* Determine what seedlen to use based on the block length */
#define MAX_BLOCKLEN_USING_SMALL_SEEDLEN (256/8)
#define INBYTE_IGNORE ((unsigned char)0xFF)


/*
 * SP800-90Ar1 10.3.1 Derivation function using a Hash Function (Hash_df).
 * The input string used is composed of:
 *    inbyte - An optional leading byte (ignore if equal to INBYTE_IGNORE)
 *    in - input string 1 (A Non NULL value).
 *    in2 - optional input string (Can be NULL).
 *    in3 - optional input string (Can be NULL).
 *    These are concatenated as part of the DigestUpdate process.
 */
static int hash_df(RAND_DRBG *drbg, unsigned char *out,
                   const unsigned char inbyte,
                   const unsigned char *in, size_t inlen,
                   const unsigned char *in2, size_t in2len,
                   const unsigned char *in3, size_t in3len)
{
    RAND_DRBG_HASH *hash = &drbg->data.hash;
    EVP_MD_CTX *ctx = hash->ctx;
    unsigned char *vtmp = hash->vtmp;
    /* tmp = counter || num_bits_returned || [inbyte] */
    unsigned char tmp[1 + 4 + 1];
    int tmp_sz = 0;
    size_t outlen = drbg->seedlen;
    size_t num_bits_returned = outlen * 8;
    /*
     * No need to check outlen size here, as the standard only ever needs
     * seedlen bytes which is always less than the maximum permitted.
     */

    /* (Step 3) counter = 1 (tmp[0] is the 8 bit counter) */
    tmp[tmp_sz++] = 1;
    /* tmp[1..4] is the fixed 32 bit no_of_bits_to_return */
    tmp[tmp_sz++] = (unsigned char)((num_bits_returned >> 24) & 0xff);
    tmp[tmp_sz++] = (unsigned char)((num_bits_returned >> 16) & 0xff);
    tmp[tmp_sz++] = (unsigned char)((num_bits_returned >> 8) & 0xff);
    tmp[tmp_sz++] = (unsigned char)(num_bits_returned & 0xff);
    /* Tack the additional input byte onto the end of tmp if it exists */
    if (inbyte != INBYTE_IGNORE)
        tmp[tmp_sz++] = inbyte;

    /* (Step 4) */
    for (;;) {
        /*
         * (Step 4.1) out = out || Hash(tmp || in || [in2] || [in3])
         *            (where tmp = counter || num_bits_returned || [inbyte])
         */
        if (!(EVP_DigestInit_ex(ctx, hash->md, NULL)
                && EVP_DigestUpdate(ctx, tmp, tmp_sz)
                && EVP_DigestUpdate(ctx, in, inlen)
                && (in2 == NULL || EVP_DigestUpdate(ctx, in2, in2len))
                && (in3 == NULL || EVP_DigestUpdate(ctx, in3, in3len))))
            return 0;

        if (outlen < hash->blocklen) {
            if (!EVP_DigestFinal(ctx, vtmp, NULL))
                return 0;
            memcpy(out, vtmp, outlen);
            OPENSSL_cleanse(vtmp, hash->blocklen);
            break;
        } else if(!EVP_DigestFinal(ctx, out, NULL)) {
            return 0;
        }

        outlen -= hash->blocklen;
        if (outlen == 0)
            break;
        /* (Step 4.2) counter++ */
        tmp[0]++;
        out += hash->blocklen;
    }
    return 1;
}

/* Helper function that just passes 2 input parameters to hash_df() */
static int hash_df1(RAND_DRBG *drbg, unsigned char *out,
                    const unsigned char in_byte,
                    const unsigned char *in1, size_t in1len)
{
    return hash_df(drbg, out, in_byte, in1, in1len, NULL, 0, NULL, 0);
}

/*
 * Add 2 byte buffers together. The first elements in each buffer are the top
 * most bytes. The result is stored in the dst buffer.
 * The final carry is ignored i.e: dst =  (dst + in) mod (2^seedlen_bits).
 * where dst size is drbg->seedlen, and inlen <= drbg->seedlen.
 */
static int add_bytes(RAND_DRBG *drbg, unsigned char *dst,
                     unsigned char *in, size_t inlen)
{
    size_t i;
    int result;
    const unsigned char *add;
    unsigned char carry = 0, *d;

    assert(drbg->seedlen >= 1 && inlen >= 1 && inlen <= drbg->seedlen);

    d = &dst[drbg->seedlen - 1];
    add = &in[inlen - 1];

    for (i = inlen; i > 0; i--, d--, add--) {
        result = *d + *add + carry;
        carry = (unsigned char)(result >> 8);
        *d = (unsigned char)(result & 0xff);
    }

    if (carry != 0) {
        /* Add the carry to the top of the dst if inlen is not the same size */
        for (i = drbg->seedlen - inlen; i > 0; --i, d--) {
            *d += 1;     /* Carry can only be 1 */
            if (*d != 0) /* exit if carry doesnt propagate to the next byte */
                break;
        }
    }
    return 1;
}

/* V = (V + Hash(inbyte || V  || [additional_input]) mod (2^seedlen) */
static int add_hash_to_v(RAND_DRBG *drbg, unsigned char inbyte,
                         const unsigned char *adin, size_t adinlen)
{
    RAND_DRBG_HASH *hash = &drbg->data.hash;
    EVP_MD_CTX *ctx = hash->ctx;

    return EVP_DigestInit_ex(ctx, hash->md, NULL)
           && EVP_DigestUpdate(ctx, &inbyte, 1)
           && EVP_DigestUpdate(ctx, hash->V, drbg->seedlen)
           && (adin == NULL || EVP_DigestUpdate(ctx, adin, adinlen))
           && EVP_DigestFinal(ctx, hash->vtmp, NULL)
           && add_bytes(drbg, hash->V, hash->vtmp, hash->blocklen);
}

/*
 * The Hashgen() as listed in SP800-90Ar1 10.1.1.4 Hash_DRBG_Generate_Process.
 *
 * drbg contains the current value of V.
 * outlen is the requested number of bytes.
 * out is a buffer to return the generated bits.
 *
 * The algorithm to generate the bits is:
 *     data = V
 *     w = NULL
 *     for (i = 1 to m) {
 *        W = W || Hash(data)
 *        data = (data + 1) mod (2^seedlen)
 *     }
 *     out = Leftmost(W, outlen)
 *
 * Returns zero if an error occurs otherwise it returns 1.
 */
static int hash_gen(RAND_DRBG *drbg, unsigned char *out, size_t outlen)
{
    RAND_DRBG_HASH *hash = &drbg->data.hash;
    unsigned char one = 1;

    if (outlen == 0)
        return 1;
    memcpy(hash->vtmp, hash->V, drbg->seedlen);
    for(;;) {
        if (!EVP_DigestInit_ex(hash->ctx, hash->md, NULL)
                || !EVP_DigestUpdate(hash->ctx, hash->vtmp, drbg->seedlen))
            return 0;

        if (outlen < hash->blocklen) {
            if (!EVP_DigestFinal(hash->ctx, hash->vtmp, NULL))
                return 0;
            memcpy(out, hash->vtmp, outlen);
            return 1;
        } else {
            if (!EVP_DigestFinal(hash->ctx, out, NULL))
                return 0;
            outlen -= hash->blocklen;
            if (outlen == 0)
                break;
            out += hash->blocklen;
        }
        add_bytes(drbg, hash->vtmp, &one, 1);
    }
    return 1;
}

/*
 * SP800-90Ar1 10.1.1.2 Hash_DRBG_Instantiate_Process:
 *
 * ent is entropy input obtained from a randomness source of length ent_len.
 * nonce is a string of bytes of length nonce_len.
 * pstr is a personalization string received from an application. May be NULL.
 *
 * Returns zero if an error occurs otherwise it returns 1.
 */
static int drbg_hash_instantiate(RAND_DRBG *drbg,
                                 const unsigned char *ent, size_t ent_len,
                                 const unsigned char *nonce, size_t nonce_len,
                                 const unsigned char *pstr, size_t pstr_len)
{
    RAND_DRBG_HASH *hash = &drbg->data.hash;

    /* (Step 1-3) V = Hash_df(entropy||nonce||pers, seedlen) */
    return hash_df(drbg, hash->V, INBYTE_IGNORE,
                   ent, ent_len, nonce, nonce_len, pstr, pstr_len)
           /* (Step 4) C = Hash_df(0x00||V, seedlen) */
           && hash_df1(drbg, hash->C, 0x00, hash->V, drbg->seedlen);
}

/*
 * SP800-90Ar1 10.1.1.3 Hash_DRBG_Reseed_Process:
 *
 * ent is entropy input bytes obtained from a randomness source.
 * addin is additional input received from an application. May be NULL.
 *
 * Returns zero if an error occurs otherwise it returns 1.
 */
static int drbg_hash_reseed(RAND_DRBG *drbg,
                            const unsigned char *ent, size_t ent_len,
                            const unsigned char *adin, size_t adin_len)
{
    RAND_DRBG_HASH *hash = &drbg->data.hash;

    /* (Step 1-2) V = Hash_df(0x01 || V || entropy_input || additional_input)*/
    /* V about to be updated so use C as output instead */
    if (!hash_df(drbg, hash->C, 0x01, hash->V, drbg->seedlen, ent, ent_len,
                 adin, adin_len))
        return 0;
    memcpy(hash->V, hash->C, drbg->seedlen);
    /* (Step 4) C = Hash_df(0x00||V, seedlen) */
    return hash_df1(drbg, hash->C, 0x00, hash->V, drbg->seedlen);
}

/*
 * SP800-90Ar1 10.1.1.4 Hash_DRBG_Generate_Process:
 *
 * Generates pseudo random bytes using the drbg.
 * out is a buffer to fill with outlen bytes of pseudo random data.
 * addin is additional input received from an application. May be NULL.
 *
 * Returns zero if an error occurs otherwise it returns 1.
 */
static int drbg_hash_generate(RAND_DRBG *drbg,
                              unsigned char *out, size_t outlen,
                              const unsigned char *adin, size_t adin_len)
{
    RAND_DRBG_HASH *hash = &drbg->data.hash;
    unsigned char counter[4];
    int reseed_counter = drbg->reseed_gen_counter;

    counter[0] = (unsigned char)((reseed_counter >> 24) & 0xff);
    counter[1] = (unsigned char)((reseed_counter >> 16) & 0xff);
    counter[2] = (unsigned char)((reseed_counter >> 8) & 0xff);
    counter[3] = (unsigned char)(reseed_counter & 0xff);

    return (adin == NULL
           /* (Step 2) if adin != NULL then V = V + Hash(0x02||V||adin) */
                || adin_len == 0
                || add_hash_to_v(drbg, 0x02, adin, adin_len))
           /* (Step 3) Hashgen(outlen, V) */
           && hash_gen(drbg, out, outlen)
           /* (Step 4/5) H = V = (V + Hash(0x03||V) mod (2^seedlen_bits) */
           && add_hash_to_v(drbg, 0x03, NULL, 0)
           /* (Step 5) V = (V + H + C + reseed_counter) mod (2^seedlen_bits) */
           /* V = (V + C) mod (2^seedlen_bits) */
           && add_bytes(drbg, hash->V, hash->C, drbg->seedlen)
           /* V = (V + reseed_counter) mod (2^seedlen_bits) */
           && add_bytes(drbg, hash->V, counter, 4);
}

static int drbg_hash_uninstantiate(RAND_DRBG *drbg)
{
    EVP_MD_free(drbg->data.hash.md);
    EVP_MD_CTX_free(drbg->data.hash.ctx);
    OPENSSL_cleanse(&drbg->data.hash, sizeof(drbg->data.hash));
    return 1;
}

static RAND_DRBG_METHOD drbg_hash_meth = {
    drbg_hash_instantiate,
    drbg_hash_reseed,
    drbg_hash_generate,
    drbg_hash_uninstantiate
};

int drbg_hash_init(RAND_DRBG *drbg)
{
    EVP_MD *md;
    RAND_DRBG_HASH *hash = &drbg->data.hash;

    /*
     * Confirm digest is allowed. We allow all digests that are not XOF
     * (such as SHAKE).  In FIPS mode, the fetch will fail for non-approved
     * digests.
     */
    md = EVP_MD_fetch(drbg->libctx, ossl_prov_util_nid_to_name(drbg->type), "");
    if (md == NULL)
        return 0;

    if ((EVP_MD_flags(md) & EVP_MD_FLAG_XOF) != 0)
        return 0;

    drbg->meth = &drbg_hash_meth;

    if (hash->ctx == NULL) {
        hash->ctx = EVP_MD_CTX_new();
        if (hash->ctx == NULL) {
            EVP_MD_free(md);
            return 0;
        }
    }

    EVP_MD_free(hash->md);
    hash->md = md;

    /* These are taken from SP 800-90 10.1 Table 2 */
    hash->blocklen = EVP_MD_size(md);
    /* See SP800-57 Part1 Rev4 5.6.1 Table 3 */
    drbg->strength = 64 * (hash->blocklen >> 3);
    if (drbg->strength > 256)
        drbg->strength = 256;
    if (hash->blocklen > MAX_BLOCKLEN_USING_SMALL_SEEDLEN)
        drbg->seedlen = HASH_PRNG_MAX_SEEDLEN;
    else
        drbg->seedlen = HASH_PRNG_SMALL_SEEDLEN;

    drbg->min_entropylen = drbg->strength / 8;
    drbg->max_entropylen = DRBG_MAX_LENGTH;

    drbg->min_noncelen = drbg->min_entropylen / 2;
    drbg->max_noncelen = DRBG_MAX_LENGTH;

    drbg->max_perslen = DRBG_MAX_LENGTH;
    drbg->max_adinlen = DRBG_MAX_LENGTH;

    /* Maximum number of bits per request = 2^19  = 2^16 bytes */
    drbg->max_request = 1 << 16;

    return 1;
}
