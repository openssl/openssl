/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Helper functions for AES CBC CTS ciphers related to fips */

/*
 * Refer to SP800-38A-Addendum
 *
 * Ciphertext stealing encrypts plaintext using a block cipher, without padding
 * the message to a multiple of the block size, so the ciphertext is the same
 * size as the plaintext.
 * It does this by altering processing of the last two blocks of the message.
 * The processing of all but the last two blocks is unchanged, but a portion of
 * the second-last block's ciphertext is "stolen" to pad the last plaintext
 * block. The padded final block is then encrypted as usual.
 * The final ciphertext for the last two blocks, consists of the partial block
 * (with the "stolen" portion omitted) plus the full final block,
 * which are the same size as the original plaintext.
 * Decryption requires decrypting the final block first, then restoring the
 * stolen ciphertext to the partial block, which can then be decrypted as usual.

 * AES_CBC_CTS has 3 variants:
 *  (1) CS1 The NIST variant.
 *      If the length is a multiple of the blocksize it is the same as CBC mode.
 *      otherwise it produces C1||C2||(C(n-1))*||Cn.
 *      Where C(n-1)* is a partial block.
 *  (2) CS2
 *      If the length is a multiple of the blocksize it is the same as CBC mode.
 *      otherwise it produces C1||C2||Cn||(C(n-1))*.
 *      Where C(n-1)* is a partial block.
 *  (3) CS3 The Kerberos5 variant.
 *      Produces C1||C2||Cn||(C(n-1))* regardless of the length.
 *      If the length is a multiple of the blocksize it looks similiar to CBC mode
 *      with the last 2 blocks swapped.
 *      Otherwise it is the same as CS2.
 */

#include "e_os.h" /* strcasecmp */
#include <openssl/core_names.h>
#include "prov/ciphercommon.h"
#include "internal/nelem.h"
#include "cipher_aes_cts.h"

/* The value assigned to 0 is the default */
#define CTS_CS1 0
#define CTS_CS2 1
#define CTS_CS3 2

typedef union {
    size_t align;
    unsigned char c[16];
} aligned_16bytes;

typedef union {
    size_t align;
    unsigned char c[32];
} aligned_32bytes;

typedef struct cts_mode_name2id_st {
    unsigned int id;
    const char *name;
} CTS_MODE_NAME2ID;

static CTS_MODE_NAME2ID cts_modes[] =
{
    { CTS_CS1, OSSL_CIPHER_CTS_MODE_CS1 },
#ifndef FIPS_MODULE
    { CTS_CS2, OSSL_CIPHER_CTS_MODE_CS2 },
    { CTS_CS3, OSSL_CIPHER_CTS_MODE_CS3 },
#endif
};

const char *aes_cbc_cts_mode_id2name(unsigned int id)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(cts_modes); ++i) {
        if (cts_modes[i].id == id)
            return cts_modes[i].name;
    }
    return NULL;
}

int aes_cbc_cts_mode_name2id(const char *name)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(cts_modes); ++i) {
        if (strcasecmp(name, cts_modes[i].name) == 0)
            return (int)cts_modes[i].id;
    }
    return -1;
}

static size_t cts128_cs1_encrypt(PROV_CIPHER_CTX *ctx, const unsigned char *in,
                                 unsigned char *out, size_t len)
{
    aligned_16bytes tmp_in;
    size_t residue;

    residue = len % 16;
    len -= residue;
    if (!ctx->hw->cipher(ctx, out, in, len))
        return 0;

    if (residue == 0)
        return len;

    in += len;
    out += len;

    memset(tmp_in.c, 0, sizeof(tmp_in));
    memcpy(tmp_in.c, in, residue);
    if (!ctx->hw->cipher(ctx, out - 16 + residue, tmp_in.c, 16))
        return 0;
    return len + residue;
}

static size_t cts128_cs1_decrypt(PROV_CIPHER_CTX *ctx, const unsigned char *in,
                                 unsigned char *out, size_t len)
{
    aligned_32bytes tmp_out;
    size_t residue;

    residue = len % 16;
    if (residue == 0) {
        /* If there are no partial blocks then it is the same as CBC mode */
        if (!ctx->hw->cipher(ctx, out, in, len))
            return 0;
        return len;
    }
    len -= 16 + residue;
    if (len) {
        if (!ctx->hw->cipher(ctx, out, in, len))
            return 0;
        in += len;
        out += len;
    }

    memset(tmp_out.c, 0, sizeof(tmp_out));
    memcpy(ctx->buf, ctx->iv, 16);   /* save the iv */
    memset(ctx->iv, 0, 16);          /* use an iv of zero */
    if (!ctx->hw->cipher(ctx, tmp_out.c, in + residue, 16))
        return 0;
    memcpy(tmp_out.c + 16, ctx->iv, 16);
    memcpy(tmp_out.c, in, residue); /* Copy the partial bytes */

    memcpy(ctx->iv, ctx->buf, 16);   /* restore the iv */
    if (!ctx->hw->cipher(ctx, tmp_out.c, tmp_out.c, 32))
        return 0;
    memcpy(out, tmp_out.c, 16 + residue);
    return 16 + len + residue;
}

#ifndef FIPS_MODULE
static size_t cts128_cs3_encrypt(PROV_CIPHER_CTX *ctx, const unsigned char *in,
                                 unsigned char *out, size_t len)
{
    aligned_16bytes tmp_in;
    size_t residue;

    if (len <= 16)  /* CS3 requires 2 blocks */
        return 0;

    residue = len % 16;
    if (residue == 0)
        residue = 16;
    len -= residue;

    if (!ctx->hw->cipher(ctx, out, in, len))
        return 0;

    in += len;
    out += len;

    memset(tmp_in.c, 0, sizeof(tmp_in));
    memcpy(tmp_in.c, in, residue);
    memcpy(out, out - 16, residue);
    if (!ctx->hw->cipher(ctx, out - 16, tmp_in.c, 16))
        return 0;
    return len + residue;
}

static size_t cts128_cs3_decrypt(PROV_CIPHER_CTX *ctx, const unsigned char *in,
                                 unsigned char *out, size_t len)
{
    aligned_32bytes tmp_out;
    size_t residue;

    if (len <= 16) /* CS3 requires 2 blocks */
        return 0;

    residue = len % 16;
    if (residue == 0)
        residue = 16;
    len -= 16 + residue;

    if (len) {
        if (!ctx->hw->cipher(ctx, out, in, len))
            return 0;
        in += len;
        out += len;
    }

    memset(tmp_out.c, 0, sizeof(tmp_out));
    memcpy(ctx->buf, ctx->iv, 16);   /* save the iv */
    memset(ctx->iv, 0, 16);          /* use an iv of zero */
    if (!ctx->hw->cipher(ctx, tmp_out.c, in, 16))
        return 0;
    memcpy(tmp_out.c + 16, ctx->iv, 16);
    memcpy(tmp_out.c, in + 16, residue);

    memcpy(ctx->iv, ctx->buf, 16);   /* restore the iv */
    if (!ctx->hw->cipher(ctx, tmp_out.c, tmp_out.c, 32))
        return 0;

    memcpy(out, tmp_out.c, 16 + residue);
    return 16 + len + residue;
}

static size_t cts128_cs2_encrypt(PROV_CIPHER_CTX *ctx, const unsigned char *in,
                                 unsigned char *out, size_t len)
{
    if (len % 16 == 0) {
        /* If there are no partial blocks then it is the same as CBC mode */
        if (!ctx->hw->cipher(ctx, out, in, len))
            return 0;
        return len;
    }
    /* For partial blocks CS2 is equivalent to CS3 */
    return cts128_cs3_encrypt(ctx, in, out, len);
}

static size_t cts128_cs2_decrypt(PROV_CIPHER_CTX *ctx, const unsigned char *in,
                                 unsigned char *out, size_t len)
{
    if (len % 16 == 0) {
        /* If there are no partial blocks then it is the same as CBC mode */
        if (!ctx->hw->cipher(ctx, out, in, len))
            return 0;
        return len;
    }
    /* For partial blocks CS2 is equivalent to CS3 */
    return cts128_cs3_decrypt(ctx, in, out, len);
}
#endif

int aes_cbc_cts_block_update(void *vctx, unsigned char *out, size_t *outl,
                             size_t outsize, const unsigned char *in,
                             size_t inl)
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
    size_t sz = 0;

    if (inl < 16) /* There must be at least one block for CTS mode */
        return 0;
    if (outsize < inl)
        return 0;
    if (out == NULL) {
        *outl = inl;
        return 1;
    }

    /*
     * Return an error if the update is called multiple times, only one shot
     * is supported. We use the bufsz to mark the update.
     */
    if (ctx->bufsz > 0)
        return 0;

    if (ctx->enc) {
#ifdef FIPS_MODULE
        sz = cts128_cs1_encrypt(ctx, in, out, inl);
#else
        if (ctx->cts_mode == CTS_CS1)
            sz = cts128_cs1_encrypt(ctx, in, out, inl);
        else if (ctx->cts_mode == CTS_CS2)
            sz = cts128_cs2_encrypt(ctx, in, out, inl);
        else if (ctx->cts_mode == CTS_CS3)
            sz = cts128_cs3_encrypt(ctx, in, out, inl);
#endif
    } else {
#ifdef FIPS_MODULE
        sz = cts128_cs1_decrypt(ctx, in, out, inl);
#else
        if (ctx->cts_mode == CTS_CS1)
            sz = cts128_cs1_decrypt(ctx, in, out, inl);
        else if (ctx->cts_mode == CTS_CS2)
            sz = cts128_cs2_decrypt(ctx, in, out, inl);
        else if (ctx->cts_mode == CTS_CS3)
            sz = cts128_cs3_decrypt(ctx, in, out, inl);
#endif
    }
    if (sz == 0)
        return 0;
    ctx->bufsz = sz; /* store the size to stop multiple updates being allowed */
    *outl = sz;
    return 1;
}

int aes_cbc_cts_block_final(void *vctx, unsigned char *out, size_t *outl,
                            size_t outsize)
{
    *outl = 0;
    return 1;
}

