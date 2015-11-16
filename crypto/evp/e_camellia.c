/* crypto/evp/e_camellia.c -*- mode:C; c-file-style: "eay" -*- */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_CAMELLIA
# include <openssl/evp.h>
# include <openssl/err.h>
# include <string.h>
# include <assert.h>
# include <openssl/camellia.h>
# include "evp_locl.h"
# include "modes_lcl.h"

static int camellia_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc);

/* Camellia subkey Structure */
typedef struct {
    CAMELLIA_KEY ks;
    block128_f block;
    union {
        cbc128_f cbc;
        ctr128_f ctr;
    } stream;
} EVP_CAMELLIA_KEY;

typedef struct {
    union {
        double align;
        CAMELLIA_KEY ks;
    } ks;                       /* Camellia key schedule to use */
    int key_set;                /* Set if key initialised */
    int iv_set;                 /* Set if an iv is set */
    GCM128_CONTEXT gcm;
    int ivlen;                  /* IV length */
    int taglen;
    int tls_aad_len;            /* TLS AAD length */
    ctr128_f ctr;
} EVP_CAMELLIA_GCM_CTX;

# define MAXBITCHUNK     ((size_t)1<<(sizeof(size_t)*8-4))

/* Attribute operation for Camellia */
# define data(ctx)       EVP_C_DATA(EVP_CAMELLIA_KEY,ctx)

# if defined(AES_ASM) && (defined(__sparc) || defined(__sparc__))
/* ---------^^^ this is not a typo, just a way to detect that
 * assembler support was in general requested... */
#  include "sparc_arch.h"

extern unsigned int OPENSSL_sparcv9cap_P[];

#  define SPARC_CMLL_CAPABLE      (OPENSSL_sparcv9cap_P[1] & CFR_CAMELLIA)

void cmll_t4_set_key(const unsigned char *key, int bits, CAMELLIA_KEY *ks);
void cmll_t4_encrypt(const unsigned char *in, unsigned char *out,
                     const CAMELLIA_KEY *key);
void cmll_t4_decrypt(const unsigned char *in, unsigned char *out,
                     const CAMELLIA_KEY *key);

void cmll128_t4_cbc_encrypt(const unsigned char *in, unsigned char *out,
                            size_t len, const CAMELLIA_KEY *key,
                            unsigned char *ivec);
void cmll128_t4_cbc_decrypt(const unsigned char *in, unsigned char *out,
                            size_t len, const CAMELLIA_KEY *key,
                            unsigned char *ivec);
void cmll256_t4_cbc_encrypt(const unsigned char *in, unsigned char *out,
                            size_t len, const CAMELLIA_KEY *key,
                            unsigned char *ivec);
void cmll256_t4_cbc_decrypt(const unsigned char *in, unsigned char *out,
                            size_t len, const CAMELLIA_KEY *key,
                            unsigned char *ivec);
void cmll128_t4_ctr32_encrypt(const unsigned char *in, unsigned char *out,
                              size_t blocks, const CAMELLIA_KEY *key,
                              unsigned char *ivec);
void cmll256_t4_ctr32_encrypt(const unsigned char *in, unsigned char *out,
                              size_t blocks, const CAMELLIA_KEY *key,
                              unsigned char *ivec);

static int cmll_t4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc)
{
    int ret, mode, bits;
    EVP_CAMELLIA_KEY *dat = (EVP_CAMELLIA_KEY *) ctx->cipher_data;

    mode = ctx->cipher->flags & EVP_CIPH_MODE;
    bits = ctx->key_len * 8;

    cmll_t4_set_key(key, bits, &dat->ks);

    if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE)
        && !enc) {
        ret = 0;
        dat->block = (block128_f) cmll_t4_decrypt;
        switch (bits) {
        case 128:
            dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
                (cbc128_f) cmll128_t4_cbc_decrypt : NULL;
            break;
        case 192:
        case 256:
            dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
                (cbc128_f) cmll256_t4_cbc_decrypt : NULL;
            break;
        default:
            ret = -1;
        }
    } else {
        ret = 0;
        dat->block = (block128_f) cmll_t4_encrypt;
        switch (bits) {
        case 128:
            if (mode == EVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f) cmll128_t4_cbc_encrypt;
            else if (mode == EVP_CIPH_CTR_MODE)
                dat->stream.ctr = (ctr128_f) cmll128_t4_ctr32_encrypt;
            else
                dat->stream.cbc = NULL;
            break;
        case 192:
        case 256:
            if (mode == EVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f) cmll256_t4_cbc_encrypt;
            else if (mode == EVP_CIPH_CTR_MODE)
                dat->stream.ctr = (ctr128_f) cmll256_t4_ctr32_encrypt;
            else
                dat->stream.cbc = NULL;
            break;
        default:
            ret = -1;
        }
    }

    if (ret < 0) {
        EVPerr(EVP_F_CMLL_T4_INIT_KEY, EVP_R_CAMELLIA_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

#  define cmll_t4_cbc_cipher camellia_cbc_cipher
static int cmll_t4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len);

#  define cmll_t4_ecb_cipher camellia_ecb_cipher
static int cmll_t4_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len);

#  define cmll_t4_ofb_cipher camellia_ofb_cipher
static int cmll_t4_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len);

#  define cmll_t4_cfb_cipher camellia_cfb_cipher
static int cmll_t4_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len);

#  define cmll_t4_cfb8_cipher camellia_cfb8_cipher
static int cmll_t4_cfb8_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len);

#  define cmll_t4_cfb1_cipher camellia_cfb1_cipher
static int cmll_t4_cfb1_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len);

#  define cmll_t4_ctr_cipher camellia_ctr_cipher
static int cmll_t4_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len);

static int cmll_t4_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                const unsigned char *iv, int enc)
{
    EVP_CAMELLIA_GCM_CTX *gctx = ctx->cipher_data;
    if (!iv && !key)
        return 1;
    if (key) {
        int bits = ctx->key_len * 8;
        cmll_t4_set_key(key, bits, &gctx->ks.ks);
        CRYPTO_gcm128_init(&gctx->gcm, &gctx->ks,
                           (block128_f) cmll_t4_encrypt);
        switch (bits) {
        case 128:
            gctx->ctr = (ctr128_f) cmll128_t4_ctr32_encrypt;
            break;
        case 192:
        case 256:
            gctx->ctr = (ctr128_f) cmll256_t4_ctr32_encrypt;
            break;
        default:
            return 0;
        }
        gctx->key_set = 1;
    }
    if (iv) {
        CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
        gctx->iv_set = 1;
    }
    return 1;
}

#  define cmll_t4_gcm_cipher camellia_gcm_cipher
static int cmll_t4_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len);

#  define BLOCK_CIPHER_generic(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVP_CIPHER cmll_t4_##keylen##_##mode = { \
        nid##_##keylen##_##nmode,blocksize,keylen/8,ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        cmll_t4_init_key,               \
        cmll_t4_##mode##_cipher,        \
        NULL,                           \
        sizeof(EVP_CAMELLIA_KEY),       \
        NULL,NULL,NULL,NULL }; \
static const EVP_CIPHER camellia_##keylen##_##mode = { \
        nid##_##keylen##_##nmode,blocksize,     \
        keylen/8,ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        camellia_init_key,              \
        camellia_##mode##_cipher,       \
        NULL,                           \
        sizeof(EVP_CAMELLIA_KEY),       \
        NULL,NULL,NULL,NULL }; \
const EVP_CIPHER *EVP_camellia_##keylen##_##mode(void) \
{ return SPARC_CMLL_CAPABLE?&cmll_t4_##keylen##_##mode:&camellia_##keylen##_##mode; }

#  define BLOCK_CIPHER_custom(nid,keylen,blocksize,ivlen,mode,MODE,flags) \
static const EVP_CIPHER camellia_t4_##keylen##_##mode = { \
        nid##_##keylen##_##mode,blocksize, \
        (EVP_CIPH_##MODE##_MODE==EVP_CIPH_XTS_MODE?2:1)*keylen/8, ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        camellia_t4_##mode##_init_key,       \
        camellia_t4_##mode##_cipher,         \
        camellia_##mode##_cleanup,           \
        sizeof(EVP_CAMELLIA_##MODE##_CTX),   \
        NULL,NULL,camellia_##mode##_ctrl,NULL }; \
static const EVP_CIPHER camellia_##keylen##_##mode = { \
        nid##_##keylen##_##mode,blocksize, \
        (EVP_CIPH_##MODE##_MODE==EVP_CIPH_XTS_MODE?2:1)*keylen/8, ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        camellia_##mode##_init_key,          \
        camellia_##mode##_cipher,            \
        camellia_##mode##_cleanup,           \
        sizeof(EVP_CAMELLIA_##MODE##_CTX),   \
        NULL,NULL,camellia_##mode##_ctrl,NULL }; \
const EVP_CIPHER *EVP_camellia_##keylen##_##mode(void) \
{ return SPARC_CMLL_CAPABLE?&cmll_t4_##keylen##_##mode:&camellia_##keylen##_##mode; }

# else

#  define BLOCK_CIPHER_generic(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVP_CIPHER camellia_##keylen##_##mode = { \
        nid##_##keylen##_##nmode,blocksize,keylen/8,ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        camellia_init_key,              \
        camellia_##mode##_cipher,       \
        NULL,                           \
        sizeof(EVP_CAMELLIA_KEY),       \
        NULL,NULL,NULL,NULL }; \
const EVP_CIPHER *EVP_camellia_##keylen##_##mode(void) \
{ return &camellia_##keylen##_##mode; }

#  define BLOCK_CIPHER_custom(nid,keylen,blocksize,ivlen,mode,MODE,flags) \
static const EVP_CIPHER camellia_##keylen##_##mode = { \
        nid##_##keylen##_##mode,blocksize, \
        (EVP_CIPH_##MODE##_MODE==EVP_CIPH_XTS_MODE?2:1)*keylen/8, ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,        \
        camellia_##mode##_init_key,          \
        camellia_##mode##_cipher,            \
        camellia_##mode##_cleanup,           \
        sizeof(EVP_CAMELLIA_##MODE##_CTX),   \
        NULL,NULL,camellia_##mode##_ctrl,NULL }; \
const EVP_CIPHER *EVP_camellia_##keylen##_##mode(void) \
{ return &camellia_##keylen##_##mode; }

# endif

# define BLOCK_CIPHER_generic_pack(nid,keylen,flags)             \
        BLOCK_CIPHER_generic(nid,keylen,16,16,cbc,cbc,CBC,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)     \
        BLOCK_CIPHER_generic(nid,keylen,16,0,ecb,ecb,ECB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)      \
        BLOCK_CIPHER_generic(nid,keylen,1,16,ofb128,ofb,OFB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)   \
        BLOCK_CIPHER_generic(nid,keylen,1,16,cfb128,cfb,CFB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)   \
        BLOCK_CIPHER_generic(nid,keylen,1,16,cfb1,cfb1,CFB,flags)       \
        BLOCK_CIPHER_generic(nid,keylen,1,16,cfb8,cfb8,CFB,flags)       \
        BLOCK_CIPHER_generic(nid, keylen, 1, 16, ctr, ctr, CTR, flags)

/* The subkey for Camellia is generated. */
static int camellia_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    int ret, mode;
    EVP_CAMELLIA_KEY *dat = (EVP_CAMELLIA_KEY *) ctx->cipher_data;

    ret = Camellia_set_key(key, ctx->key_len * 8, &dat->ks);
    if (ret < 0) {
        EVPerr(EVP_F_CAMELLIA_INIT_KEY, EVP_R_CAMELLIA_KEY_SETUP_FAILED);
        return 0;
    }

    mode = ctx->cipher->flags & EVP_CIPH_MODE;
    if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE)
        && !enc) {
        dat->block = (block128_f) Camellia_decrypt;
        dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
            (cbc128_f) Camellia_cbc_encrypt : NULL;
    } else {
        dat->block = (block128_f) Camellia_encrypt;
        dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
            (cbc128_f) Camellia_cbc_encrypt : NULL;
    }

    return 1;
}

static int camellia_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    EVP_CAMELLIA_KEY *dat = (EVP_CAMELLIA_KEY *) ctx->cipher_data;

    if (dat->stream.cbc)
        (*dat->stream.cbc) (in, out, len, &dat->ks, ctx->iv, ctx->encrypt);
    else if (ctx->encrypt)
        CRYPTO_cbc128_encrypt(in, out, len, &dat->ks, ctx->iv, dat->block);
    else
        CRYPTO_cbc128_decrypt(in, out, len, &dat->ks, ctx->iv, dat->block);

    return 1;
}

static int camellia_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    size_t bl = ctx->cipher->block_size;
    size_t i;
    EVP_CAMELLIA_KEY *dat = (EVP_CAMELLIA_KEY *) ctx->cipher_data;

    if (len < bl)
        return 1;

    for (i = 0, len -= bl; i <= len; i += bl)
        (*dat->block) (in + i, out + i, &dat->ks);

    return 1;
}

static int camellia_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    EVP_CAMELLIA_KEY *dat = (EVP_CAMELLIA_KEY *) ctx->cipher_data;

    CRYPTO_ofb128_encrypt(in, out, len, &dat->ks,
                          ctx->iv, &ctx->num, dat->block);
    return 1;
}

static int camellia_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    EVP_CAMELLIA_KEY *dat = (EVP_CAMELLIA_KEY *) ctx->cipher_data;

    CRYPTO_cfb128_encrypt(in, out, len, &dat->ks,
                          ctx->iv, &ctx->num, ctx->encrypt, dat->block);
    return 1;
}

static int camellia_cfb8_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                const unsigned char *in, size_t len)
{
    EVP_CAMELLIA_KEY *dat = (EVP_CAMELLIA_KEY *) ctx->cipher_data;

    CRYPTO_cfb128_8_encrypt(in, out, len, &dat->ks,
                            ctx->iv, &ctx->num, ctx->encrypt, dat->block);
    return 1;
}

static int camellia_cfb1_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                const unsigned char *in, size_t len)
{
    EVP_CAMELLIA_KEY *dat = (EVP_CAMELLIA_KEY *) ctx->cipher_data;

    if (ctx->flags & EVP_CIPH_FLAG_LENGTH_BITS) {
        CRYPTO_cfb128_1_encrypt(in, out, len, &dat->ks,
                                ctx->iv, &ctx->num, ctx->encrypt, dat->block);
        return 1;
    }

    while (len >= MAXBITCHUNK) {
        CRYPTO_cfb128_1_encrypt(in, out, MAXBITCHUNK * 8, &dat->ks,
                                ctx->iv, &ctx->num, ctx->encrypt, dat->block);
        len -= MAXBITCHUNK;
    }
    if (len)
        CRYPTO_cfb128_1_encrypt(in, out, len * 8, &dat->ks,
                                ctx->iv, &ctx->num, ctx->encrypt, dat->block);

    return 1;
}

static int camellia_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    unsigned int num = ctx->num;
    EVP_CAMELLIA_KEY *dat = (EVP_CAMELLIA_KEY *) ctx->cipher_data;

    if (dat->stream.ctr)
        CRYPTO_ctr128_encrypt_ctr32(in, out, len, &dat->ks,
                                    ctx->iv, ctx->buf, &num, dat->stream.ctr);
    else
        CRYPTO_ctr128_encrypt(in, out, len, &dat->ks,
                              ctx->iv, ctx->buf, &num, dat->block);
    ctx->num = (size_t)num;
    return 1;
}

BLOCK_CIPHER_generic_pack(NID_camellia, 128, 0)
    BLOCK_CIPHER_generic_pack(NID_camellia, 192, 0)
    BLOCK_CIPHER_generic_pack(NID_camellia, 256, 0)

static int camellia_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                 const unsigned char *iv, int enc)
{
    EVP_CAMELLIA_GCM_CTX *gctx = ctx->cipher_data;
    if (!iv && !key)
        return 1;
    if (key) {
        do {
            Camellia_set_key(key, ctx->key_len * 8, &gctx->ks.ks);
            CRYPTO_gcm128_init(&gctx->gcm, &gctx->ks,
                               (block128_f) Camellia_encrypt);
            gctx->ctr = NULL;
        } while (0);
        gctx->key_set = 1;
    }
    if (iv) {
        CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
        gctx->iv_set = 1;
    }
    return 1;
}

static int camellia_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
    EVP_CAMELLIA_GCM_CTX *gctx = c->cipher_data;
    switch (type) {
    case EVP_CTRL_INIT:
        gctx->key_set = 0;
        gctx->iv_set = 0;
        gctx->ivlen = c->cipher->iv_len;
        gctx->taglen = -1;
        gctx->tls_aad_len = -1;
        return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
        if (arg <= 0)
            return 0;
        gctx->ivlen = arg;
        return 1;

    case EVP_CTRL_AEAD_SET_TAG:
        if (arg <= 0 || arg > 16 || c->encrypt)
            return 0;
        memcpy(c->buf, ptr, arg);
        gctx->taglen = arg;
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        if (arg <= 0 || arg > 16 || !c->encrypt || gctx->taglen < 0)
            return 0;
        memcpy(ptr, c->buf, arg);
        return 1;

    case EVP_CTRL_GCM_SET_IV_FIXED:
        /* Sanity check length */
        if (arg != EVP_GCM_TLS_FIXED_IV_LEN)
            return 0;
        /* Just copy to first part of IV */
        memcpy(c->iv, ptr, arg);
        return 1;

    case EVP_CTRL_AEAD_TLS1_AAD:
        /* Save the AAD for later use */
        if (arg != EVP_AEAD_TLS1_AAD_LEN)
            return 0;
        memcpy(c->buf, ptr, arg);
        gctx->tls_aad_len = arg;
        {
            unsigned int len = c->buf[arg - 2] << 8 | c->buf[arg - 1];
            /* Correct length for explicit IV */
            len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
            /* If decrypting correct for tag too */
            if (!c->encrypt)
                len -= EVP_GCM_TLS_TAG_LEN;
            c->buf[arg - 2] = len >> 8;
            c->buf[arg - 1] = len & 0xff;
        }
        /* Extra padding: tag appended to record */
        return EVP_GCM_TLS_TAG_LEN;

    case EVP_CTRL_COPY:
        {
            EVP_CIPHER_CTX *out = ptr;
            EVP_CAMELLIA_GCM_CTX *gctx_out = out->cipher_data;
            if (gctx->gcm.key) {
                if (gctx->gcm.key != &gctx->ks)
                    return 0;
                gctx_out->gcm.key = &gctx_out->ks;
            }
            return 1;
        }

    default:
        return -1;

    }
}

static int camellia_gcm_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                   const unsigned char *in, size_t len)
{
    EVP_CAMELLIA_GCM_CTX *gctx = ctx->cipher_data;
    int rv = -1;
    /* Encrypt/decrypt must be performed in place */
    if (out != in || len < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN))
        return -1;
    /* If encrypting set explicit IV from sequence number (start of AAD) */
    if (ctx->encrypt)
        memcpy(out, ctx->buf, EVP_GCM_TLS_EXPLICIT_IV_LEN);
    /* Get rest of IV from explicit IV */
    memcpy(ctx->iv + EVP_GCM_TLS_FIXED_IV_LEN, in, EVP_GCM_TLS_EXPLICIT_IV_LEN);
    CRYPTO_gcm128_setiv(&gctx->gcm, ctx->iv, gctx->ivlen);
    /* Use saved AAD */
    if (CRYPTO_gcm128_aad(&gctx->gcm, ctx->buf, gctx->tls_aad_len))
        goto err;
    /* Fix buffer and length to point to payload */
    in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    if (ctx->encrypt) {
        /* Encrypt payload */
        if (gctx->ctr) {
            size_t bulk = 0;
            if (CRYPTO_gcm128_encrypt_ctr32(&gctx->gcm,
                                            in + bulk,
                                            out + bulk,
                                            len - bulk, gctx->ctr))
                goto err;
        } else {
            size_t bulk = 0;
            if (CRYPTO_gcm128_encrypt(&gctx->gcm,
                                      in + bulk, out + bulk, len - bulk))
                goto err;
        }
        out += len;
        /* Finally write tag */
        CRYPTO_gcm128_tag(&gctx->gcm, out, EVP_GCM_TLS_TAG_LEN);
        rv = len + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    } else {
        /* Decrypt */
        if (gctx->ctr) {
            size_t bulk = 0;
            if (CRYPTO_gcm128_decrypt_ctr32(&gctx->gcm,
                                            in + bulk,
                                            out + bulk,
                                            len - bulk, gctx->ctr))
                goto err;
        } else {
            size_t bulk = 0;
            if (CRYPTO_gcm128_decrypt(&gctx->gcm,
                                      in + bulk, out + bulk, len - bulk))
                goto err;
        }
        /* Retrieve tag */
        CRYPTO_gcm128_tag(&gctx->gcm, ctx->buf, EVP_GCM_TLS_TAG_LEN);
        /* If tag mismatch wipe buffer */
        if (CRYPTO_memcmp(ctx->buf, in + len, EVP_GCM_TLS_TAG_LEN)) {
            OPENSSL_cleanse(out, len);
            goto err;
        }
        rv = len;
    }

 err:
    gctx->iv_set = 0;
    gctx->tls_aad_len = -1;
    return rv;
}

static int camellia_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    EVP_CAMELLIA_GCM_CTX *gctx = ctx->cipher_data;
    /* If not set up, return error */
    if (!gctx->key_set)
        return -1;

    if (gctx->tls_aad_len >= 0)
        return camellia_gcm_tls_cipher(ctx, out, in, len);

    if (!gctx->iv_set)
        return -1;
    if (in) {
        if (out == NULL) {
            if (CRYPTO_gcm128_aad(&gctx->gcm, in, len))
                return -1;
        } else if (ctx->encrypt) {
            if (gctx->ctr) {
                size_t bulk = 0;
                if (CRYPTO_gcm128_encrypt_ctr32(&gctx->gcm,
                                                in + bulk,
                                                out + bulk,
                                                len - bulk, gctx->ctr))
                    return -1;
            } else {
                size_t bulk = 0;
                if (CRYPTO_gcm128_encrypt(&gctx->gcm,
                                          in + bulk, out + bulk, len - bulk))
                    return -1;
            }
        } else {
            if (gctx->ctr) {
                size_t bulk = 0;
                if (CRYPTO_gcm128_decrypt_ctr32(&gctx->gcm,
                                                in + bulk,
                                                out + bulk,
                                                len - bulk, gctx->ctr))
                    return -1;
            } else {
                size_t bulk = 0;
                if (CRYPTO_gcm128_decrypt(&gctx->gcm,
                                          in + bulk, out + bulk, len - bulk))
                    return -1;
            }
        }
        return len;
    } else {
        if (!ctx->encrypt) {
            if (gctx->taglen < 0)
                return -1;
            if (CRYPTO_gcm128_finish(&gctx->gcm, ctx->buf, gctx->taglen) != 0)
                return -1;
            gctx->iv_set = 0;
            return 0;
        }
        CRYPTO_gcm128_tag(&gctx->gcm, ctx->buf, 16);
        gctx->taglen = 16;
        /* Don't reuse the IV */
        gctx->iv_set = 0;
        return 0;
    }

}

# define camellia_gcm_cleanup NULL

# define CUSTOM_FLAGS    (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                | EVP_CIPH_CUSTOM_COPY)

BLOCK_CIPHER_custom(NID_camellia, 128, 1, 12, gcm, GCM,
                    EVP_CIPH_FLAG_AEAD_CIPHER | CUSTOM_FLAGS)
    BLOCK_CIPHER_custom(NID_camellia, 192, 1, 12, gcm, GCM,
                    EVP_CIPH_FLAG_AEAD_CIPHER | CUSTOM_FLAGS)
    BLOCK_CIPHER_custom(NID_camellia, 256, 1, 12, gcm, GCM,
                    EVP_CIPH_FLAG_AEAD_CIPHER | CUSTOM_FLAGS)

#else

# ifdef PEDANTIC
static void *dummy = &dummy;
# endif

#endif
