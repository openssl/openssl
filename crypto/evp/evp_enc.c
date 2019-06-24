/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <assert.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rand_drbg.h>
#include <openssl/engine.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include "internal/evp_int.h"
#include "internal/provider.h"
#include "evp_locl.h"

int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *ctx)
{
    if (ctx == NULL)
        return 1;

    if (ctx->cipher == NULL || ctx->cipher->prov == NULL)
        goto legacy;

    if (ctx->provctx != NULL) {
        if (ctx->cipher->freectx != NULL)
            ctx->cipher->freectx(ctx->provctx);
        ctx->provctx = NULL;
    }
    if (ctx->fetched_cipher != NULL)
        EVP_CIPHER_meth_free(ctx->fetched_cipher);
    memset(ctx, 0, sizeof(*ctx));

    return 1;

    /* TODO(3.0): Remove legacy code below */
 legacy:

    if (ctx->cipher != NULL) {
        if (ctx->cipher->cleanup && !ctx->cipher->cleanup(ctx))
            return 0;
        /* Cleanse cipher context data */
        if (ctx->cipher_data && ctx->cipher->ctx_size)
            OPENSSL_cleanse(ctx->cipher_data, ctx->cipher->ctx_size);
    }
    OPENSSL_free(ctx->cipher_data);
#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODE)
    ENGINE_finish(ctx->engine);
#endif
    memset(ctx, 0, sizeof(*ctx));
    return 1;
}

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void)
{
    return OPENSSL_zalloc(sizeof(EVP_CIPHER_CTX));
}

void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx)
{
    EVP_CIPHER_CTX_reset(ctx);
    OPENSSL_free(ctx);
}

int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                   const unsigned char *key, const unsigned char *iv, int enc)
{
    if (cipher != NULL)
        EVP_CIPHER_CTX_reset(ctx);
    return EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc);
}

int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                      ENGINE *impl, const unsigned char *key,
                      const unsigned char *iv, int enc)
{
#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODE)
    ENGINE *tmpimpl = NULL;
#endif
    const EVP_CIPHER *tmpcipher;

    /*
     * enc == 1 means we are encrypting.
     * enc == 0 means we are decrypting.
     * enc == -1 means, use the previously initialised value for encrypt/decrypt
     */
    if (enc == -1) {
        enc = ctx->encrypt;
    } else {
        if (enc)
            enc = 1;
        ctx->encrypt = enc;
    }

    if (cipher == NULL && ctx->cipher == NULL) {
        EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_NO_CIPHER_SET);
        return 0;
    }

    /* TODO(3.0): Legacy work around code below. Remove this */

#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODE)
    /*
     * Whether it's nice or not, "Inits" can be used on "Final"'d contexts so
     * this context may already have an ENGINE! Try to avoid releasing the
     * previous handle, re-querying for an ENGINE, and having a
     * reinitialisation, when it may all be unnecessary.
     */
    if (ctx->engine && ctx->cipher
        && (cipher == NULL || cipher->nid == ctx->cipher->nid))
        goto skip_to_init;

    if (cipher != NULL && impl == NULL) {
         /* Ask if an ENGINE is reserved for this job */
        tmpimpl = ENGINE_get_cipher_engine(cipher->nid);
    }
#endif

    /*
     * If there are engines involved then we should use legacy handling for now.
     */
    if (ctx->engine != NULL
#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODE)
            || tmpimpl != NULL
#endif
            || impl != NULL) {
        if (ctx->cipher == ctx->fetched_cipher)
            ctx->cipher = NULL;
        EVP_CIPHER_meth_free(ctx->fetched_cipher);
        ctx->fetched_cipher = NULL;
        goto legacy;
    }

    tmpcipher = (cipher == NULL) ? ctx->cipher : cipher;

    if (tmpcipher->prov == NULL) {
        switch(tmpcipher->nid) {
        case NID_aes_256_ecb:
        case NID_aes_192_ecb:
        case NID_aes_128_ecb:
        case NID_aes_256_cbc:
        case NID_aes_192_cbc:
        case NID_aes_128_cbc:
        case NID_aes_256_ofb128:
        case NID_aes_192_ofb128:
        case NID_aes_128_ofb128:
        case NID_aes_256_cfb128:
        case NID_aes_192_cfb128:
        case NID_aes_128_cfb128:
        case NID_aes_256_cfb1:
        case NID_aes_192_cfb1:
        case NID_aes_128_cfb1:
        case NID_aes_256_cfb8:
        case NID_aes_192_cfb8:
        case NID_aes_128_cfb8:
        case NID_aes_256_ctr:
        case NID_aes_192_ctr:
        case NID_aes_128_ctr:
            break;
        default:
            goto legacy;
        }
    }

    /*
     * Ensure a context left lying around from last time is cleared
     * (legacy code)
     */
    if (cipher != NULL && ctx->cipher != NULL) {
        OPENSSL_clear_free(ctx->cipher_data, ctx->cipher->ctx_size);
        ctx->cipher_data = NULL;
    }


    /* TODO(3.0): Start of non-legacy code below */

    /* Ensure a context left lying around from last time is cleared */
    if (cipher != NULL && ctx->cipher != NULL) {
        unsigned long flags = ctx->flags;

        EVP_CIPHER_CTX_reset(ctx);
        /* Restore encrypt and flags */
        ctx->encrypt = enc;
        ctx->flags = flags;
    }

    if (cipher != NULL)
        ctx->cipher = cipher;
    else
        cipher = ctx->cipher;

    if (cipher->prov == NULL) {
#ifdef FIPS_MODE
        /* We only do explict fetches inside the FIPS module */
        EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_INITIALIZATION_ERROR);
        return 0;
#else
        EVP_CIPHER *provciph =
            EVP_CIPHER_fetch(NULL, OBJ_nid2sn(cipher->nid), "");

        if (provciph == NULL) {
            EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_INITIALIZATION_ERROR);
            return 0;
        }
        cipher = provciph;
        EVP_CIPHER_meth_free(ctx->fetched_cipher);
        ctx->fetched_cipher = provciph;
#endif
    }

    ctx->cipher = cipher;
    if (ctx->provctx == NULL) {
        ctx->provctx = ctx->cipher->newctx(ossl_provider_ctx(cipher->prov));
        if (ctx->provctx == NULL) {
            EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_INITIALIZATION_ERROR);
            return 0;
        }
    }

    if ((ctx->flags & EVP_CIPH_NO_PADDING) != 0) {
        /*
         * If this ctx was already set up for no padding then we need to tell
         * the new cipher about it.
         */
        if (!EVP_CIPHER_CTX_set_padding(ctx, 0))
            return 0;
    }

    switch (EVP_CIPHER_mode(ctx->cipher)) {
    case EVP_CIPH_CFB_MODE:
    case EVP_CIPH_OFB_MODE:
    case EVP_CIPH_CBC_MODE:
        /* For these modes we remember the original IV for later use */
        if (!ossl_assert(EVP_CIPHER_CTX_iv_length(ctx) <= (int)sizeof(ctx->oiv))) {
            EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_INITIALIZATION_ERROR);
            return 0;
        }
        if (iv != NULL)
            memcpy(ctx->oiv, iv, EVP_CIPHER_CTX_iv_length(ctx));
    }

    if (enc) {
        if (ctx->cipher->einit == NULL) {
            EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_INITIALIZATION_ERROR);
            return 0;
        }

        return ctx->cipher->einit(ctx->provctx,
                                  key,
                                  key == NULL ? 0
                                              : EVP_CIPHER_CTX_key_length(ctx),
                                  iv,
                                  iv == NULL ? 0
                                             : EVP_CIPHER_CTX_iv_length(ctx));
    }

    if (ctx->cipher->dinit == NULL) {
        EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_INITIALIZATION_ERROR);
        return 0;
    }

    return ctx->cipher->dinit(ctx->provctx,
                              key,
                              key == NULL ? 0
                                          : EVP_CIPHER_CTX_key_length(ctx),
                              iv,
                              iv == NULL ? 0
                                         : EVP_CIPHER_CTX_iv_length(ctx));

    /* TODO(3.0): Remove legacy code below */
 legacy:

    if (cipher != NULL) {
        /*
         * Ensure a context left lying around from last time is cleared (we
         * previously attempted to avoid this if the same ENGINE and
         * EVP_CIPHER could be used).
         */
        if (ctx->cipher) {
            unsigned long flags = ctx->flags;
            EVP_CIPHER_CTX_reset(ctx);
            /* Restore encrypt and flags */
            ctx->encrypt = enc;
            ctx->flags = flags;
        }
#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODE)
        if (impl != NULL) {
            if (!ENGINE_init(impl)) {
                EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_INITIALIZATION_ERROR);
                return 0;
            }
        } else {
            impl = tmpimpl;
        }
        if (impl != NULL) {
            /* There's an ENGINE for this job ... (apparently) */
            const EVP_CIPHER *c = ENGINE_get_cipher(impl, cipher->nid);

            if (c == NULL) {
                /*
                 * One positive side-effect of US's export control history,
                 * is that we should at least be able to avoid using US
                 * misspellings of "initialisation"?
                 */
                EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_INITIALIZATION_ERROR);
                return 0;
            }
            /* We'll use the ENGINE's private cipher definition */
            cipher = c;
            /*
             * Store the ENGINE functional reference so we know 'cipher' came
             * from an ENGINE and we need to release it when done.
             */
            ctx->engine = impl;
        } else {
            ctx->engine = NULL;
        }
#endif

        ctx->cipher = cipher;
        if (ctx->cipher->ctx_size) {
            ctx->cipher_data = OPENSSL_zalloc(ctx->cipher->ctx_size);
            if (ctx->cipher_data == NULL) {
                ctx->cipher = NULL;
                EVPerr(EVP_F_EVP_CIPHERINIT_EX, ERR_R_MALLOC_FAILURE);
                return 0;
            }
        } else {
            ctx->cipher_data = NULL;
        }
        ctx->key_len = cipher->key_len;
        /* Preserve wrap enable flag, zero everything else */
        ctx->flags &= EVP_CIPHER_CTX_FLAG_WRAP_ALLOW;
        if (ctx->cipher->flags & EVP_CIPH_CTRL_INIT) {
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_INIT, 0, NULL)) {
                ctx->cipher = NULL;
                EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_INITIALIZATION_ERROR);
                return 0;
            }
        }
    }
#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODE)
 skip_to_init:
#endif
    if (ctx->cipher == NULL)
        return 0;

    /* we assume block size is a power of 2 in *cryptUpdate */
    OPENSSL_assert(ctx->cipher->block_size == 1
                   || ctx->cipher->block_size == 8
                   || ctx->cipher->block_size == 16);

    if (!(ctx->flags & EVP_CIPHER_CTX_FLAG_WRAP_ALLOW)
        && EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_WRAP_MODE) {
        EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_WRAP_MODE_NOT_ALLOWED);
        return 0;
    }

    if (!(EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(ctx)) & EVP_CIPH_CUSTOM_IV)) {
        switch (EVP_CIPHER_CTX_mode(ctx)) {

        case EVP_CIPH_STREAM_CIPHER:
        case EVP_CIPH_ECB_MODE:
            break;

        case EVP_CIPH_CFB_MODE:
        case EVP_CIPH_OFB_MODE:

            ctx->num = 0;
            /* fall-through */

        case EVP_CIPH_CBC_MODE:

            OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) <=
                           (int)sizeof(ctx->iv));
            if (iv)
                memcpy(ctx->oiv, iv, EVP_CIPHER_CTX_iv_length(ctx));
            memcpy(ctx->iv, ctx->oiv, EVP_CIPHER_CTX_iv_length(ctx));
            break;

        case EVP_CIPH_CTR_MODE:
            ctx->num = 0;
            /* Don't reuse IV for CTR mode */
            if (iv)
                memcpy(ctx->iv, iv, EVP_CIPHER_CTX_iv_length(ctx));
            break;

        default:
            return 0;
        }
    }

    if (key || (ctx->cipher->flags & EVP_CIPH_ALWAYS_CALL_INIT)) {
        if (!ctx->cipher->init(ctx, key, iv, enc))
            return 0;
    }
    ctx->buf_len = 0;
    ctx->final_used = 0;
    ctx->block_mask = ctx->cipher->block_size - 1;
    return 1;
}

int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl)
{
    if (ctx->encrypt)
        return EVP_EncryptUpdate(ctx, out, outl, in, inl);
    else
        return EVP_DecryptUpdate(ctx, out, outl, in, inl);
}

int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    if (ctx->encrypt)
        return EVP_EncryptFinal_ex(ctx, out, outl);
    else
        return EVP_DecryptFinal_ex(ctx, out, outl);
}

int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    if (ctx->encrypt)
        return EVP_EncryptFinal(ctx, out, outl);
    else
        return EVP_DecryptFinal(ctx, out, outl);
}

int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                    const unsigned char *key, const unsigned char *iv)
{
    return EVP_CipherInit(ctx, cipher, key, iv, 1);
}

int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                       ENGINE *impl, const unsigned char *key,
                       const unsigned char *iv)
{
    return EVP_CipherInit_ex(ctx, cipher, impl, key, iv, 1);
}

int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                    const unsigned char *key, const unsigned char *iv)
{
    return EVP_CipherInit(ctx, cipher, key, iv, 0);
}

int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                       ENGINE *impl, const unsigned char *key,
                       const unsigned char *iv)
{
    return EVP_CipherInit_ex(ctx, cipher, impl, key, iv, 0);
}

/*
 * According to the letter of standard difference between pointers
 * is specified to be valid only within same object. This makes
 * it formally challenging to determine if input and output buffers
 * are not partially overlapping with standard pointer arithmetic.
 */
#ifdef PTRDIFF_T
# undef PTRDIFF_T
#endif
#if defined(OPENSSL_SYS_VMS) && __INITIAL_POINTER_SIZE==64
/*
 * Then we have VMS that distinguishes itself by adhering to
 * sizeof(size_t)==4 even in 64-bit builds, which means that
 * difference between two pointers might be truncated to 32 bits.
 * In the context one can even wonder how comparison for
 * equality is implemented. To be on the safe side we adhere to
 * PTRDIFF_T even for comparison for equality.
 */
# define PTRDIFF_T uint64_t
#else
# define PTRDIFF_T size_t
#endif

int is_partially_overlapping(const void *ptr1, const void *ptr2, int len)
{
    PTRDIFF_T diff = (PTRDIFF_T)ptr1-(PTRDIFF_T)ptr2;
    /*
     * Check for partially overlapping buffers. [Binary logical
     * operations are used instead of boolean to minimize number
     * of conditional branches.]
     */
    int overlapped = (len > 0) & (diff != 0) & ((diff < (PTRDIFF_T)len) |
                                                (diff > (0 - (PTRDIFF_T)len)));

    return overlapped;
}

static int evp_EncryptDecryptUpdate(EVP_CIPHER_CTX *ctx,
                                    unsigned char *out, int *outl,
                                    const unsigned char *in, int inl)
{
    int i, j, bl, cmpl = inl;

    if (EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS))
        cmpl = (cmpl + 7) / 8;

    bl = ctx->cipher->block_size;

    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        /* If block size > 1 then the cipher will have to do this check */
        if (bl == 1 && is_partially_overlapping(out, in, cmpl)) {
            EVPerr(EVP_F_EVP_ENCRYPTDECRYPTUPDATE, EVP_R_PARTIALLY_OVERLAPPING);
            return 0;
        }

        i = ctx->cipher->do_cipher(ctx, out, in, inl);
        if (i < 0)
            return 0;
        else
            *outl = i;
        return 1;
    }

    if (inl <= 0) {
        *outl = 0;
        return inl == 0;
    }
    if (is_partially_overlapping(out + ctx->buf_len, in, cmpl)) {
        EVPerr(EVP_F_EVP_ENCRYPTDECRYPTUPDATE, EVP_R_PARTIALLY_OVERLAPPING);
        return 0;
    }

    if (ctx->buf_len == 0 && (inl & (ctx->block_mask)) == 0) {
        if (ctx->cipher->do_cipher(ctx, out, in, inl)) {
            *outl = inl;
            return 1;
        } else {
            *outl = 0;
            return 0;
        }
    }
    i = ctx->buf_len;
    OPENSSL_assert(bl <= (int)sizeof(ctx->buf));
    if (i != 0) {
        if (bl - i > inl) {
            memcpy(&(ctx->buf[i]), in, inl);
            ctx->buf_len += inl;
            *outl = 0;
            return 1;
        } else {
            j = bl - i;
            memcpy(&(ctx->buf[i]), in, j);
            inl -= j;
            in += j;
            if (!ctx->cipher->do_cipher(ctx, out, ctx->buf, bl))
                return 0;
            out += bl;
            *outl = bl;
        }
    } else
        *outl = 0;
    i = inl & (bl - 1);
    inl -= i;
    if (inl > 0) {
        if (!ctx->cipher->do_cipher(ctx, out, in, inl))
            return 0;
        *outl += inl;
    }

    if (i != 0)
        memcpy(ctx->buf, &(in[inl]), i);
    ctx->buf_len = i;
    return 1;
}


int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl)
{
    int ret;
    size_t soutl;
    int blocksize;

    /* Prevent accidental use of decryption context when encrypting */
    if (!ctx->encrypt) {
        EVPerr(EVP_F_EVP_ENCRYPTUPDATE, EVP_R_INVALID_OPERATION);
        return 0;
    }

    if (ctx->cipher == NULL) {
        EVPerr(EVP_F_EVP_ENCRYPTUPDATE, EVP_R_NO_CIPHER_SET);
        return 0;
    }

    if (ctx->cipher->prov == NULL)
        goto legacy;

    blocksize = EVP_CIPHER_CTX_block_size(ctx);

    if (ctx->cipher->cupdate == NULL  || blocksize < 1) {
        EVPerr(EVP_F_EVP_ENCRYPTUPDATE, EVP_R_UPDATE_ERROR);
        return 0;
    }
    ret = ctx->cipher->cupdate(ctx->provctx, out, &soutl,
                               inl + (blocksize == 1 ? 0 : blocksize), in,
                               (size_t)inl);

    if (ret) {
        if (soutl > INT_MAX) {
            EVPerr(EVP_F_EVP_ENCRYPTUPDATE, EVP_R_UPDATE_ERROR);
            return 0;
        }
        *outl = soutl;
    }

    return ret;

    /* TODO(3.0): Remove legacy code below */
 legacy:

    return evp_EncryptDecryptUpdate(ctx, out, outl, in, inl);
}

int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int ret;
    ret = EVP_EncryptFinal_ex(ctx, out, outl);
    return ret;
}

int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int n, ret;
    unsigned int i, b, bl;
    size_t soutl;
    int blocksize;

    /* Prevent accidental use of decryption context when encrypting */
    if (!ctx->encrypt) {
        EVPerr(EVP_F_EVP_ENCRYPTFINAL_EX, EVP_R_INVALID_OPERATION);
        return 0;
    }

    if (ctx->cipher == NULL) {
        EVPerr(EVP_F_EVP_ENCRYPTFINAL_EX, EVP_R_NO_CIPHER_SET);
        return 0;
    }
    if (ctx->cipher->prov == NULL)
        goto legacy;

    blocksize = EVP_CIPHER_CTX_block_size(ctx);

    if (blocksize < 1 || ctx->cipher->cfinal == NULL) {
        EVPerr(EVP_F_EVP_ENCRYPTFINAL_EX, EVP_R_FINAL_ERROR);
        return 0;
    }

    ret = ctx->cipher->cfinal(ctx->provctx, out, &soutl,
                              blocksize == 1 ? 0 : blocksize);

    if (ret) {
        if (soutl > INT_MAX) {
            EVPerr(EVP_F_EVP_ENCRYPTFINAL_EX, EVP_R_FINAL_ERROR);
            return 0;
        }
        *outl = soutl;
    }

    return ret;

    /* TODO(3.0): Remove legacy code below */
 legacy:

    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        ret = ctx->cipher->do_cipher(ctx, out, NULL, 0);
        if (ret < 0)
            return 0;
        else
            *outl = ret;
        return 1;
    }

    b = ctx->cipher->block_size;
    OPENSSL_assert(b <= sizeof(ctx->buf));
    if (b == 1) {
        *outl = 0;
        return 1;
    }
    bl = ctx->buf_len;
    if (ctx->flags & EVP_CIPH_NO_PADDING) {
        if (bl) {
            EVPerr(EVP_F_EVP_ENCRYPTFINAL_EX,
                   EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH);
            return 0;
        }
        *outl = 0;
        return 1;
    }

    n = b - bl;
    for (i = bl; i < b; i++)
        ctx->buf[i] = n;
    ret = ctx->cipher->do_cipher(ctx, out, ctx->buf, b);

    if (ret)
        *outl = b;

    return ret;
}

int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl)
{
    int fix_len, cmpl = inl, ret;
    unsigned int b;
    size_t soutl;
    int blocksize;

    /* Prevent accidental use of encryption context when decrypting */
    if (ctx->encrypt) {
        EVPerr(EVP_F_EVP_DECRYPTUPDATE, EVP_R_INVALID_OPERATION);
        return 0;
    }

    if (ctx->cipher == NULL) {
        EVPerr(EVP_F_EVP_DECRYPTUPDATE, EVP_R_NO_CIPHER_SET);
        return 0;
    }
    if (ctx->cipher->prov == NULL)
        goto legacy;

    blocksize = EVP_CIPHER_CTX_block_size(ctx);

    if (ctx->cipher->cupdate == NULL || blocksize < 1) {
        EVPerr(EVP_F_EVP_DECRYPTUPDATE, EVP_R_UPDATE_ERROR);
        return 0;
    }
    ret = ctx->cipher->cupdate(ctx->provctx, out, &soutl,
                               inl + (blocksize == 1 ? 0 : blocksize), in,
                               (size_t)inl);

    if (ret) {
        if (soutl > INT_MAX) {
            EVPerr(EVP_F_EVP_DECRYPTUPDATE, EVP_R_UPDATE_ERROR);
            return 0;
        }
        *outl = soutl;
    }

    return ret;

    /* TODO(3.0): Remove legacy code below */
 legacy:

    b = ctx->cipher->block_size;

    if (EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS))
        cmpl = (cmpl + 7) / 8;

    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        if (b == 1 && is_partially_overlapping(out, in, cmpl)) {
            EVPerr(EVP_F_EVP_DECRYPTUPDATE, EVP_R_PARTIALLY_OVERLAPPING);
            return 0;
        }

        fix_len = ctx->cipher->do_cipher(ctx, out, in, inl);
        if (fix_len < 0) {
            *outl = 0;
            return 0;
        } else
            *outl = fix_len;
        return 1;
    }

    if (inl <= 0) {
        *outl = 0;
        return inl == 0;
    }

    if (ctx->flags & EVP_CIPH_NO_PADDING)
        return evp_EncryptDecryptUpdate(ctx, out, outl, in, inl);

    OPENSSL_assert(b <= sizeof(ctx->final));

    if (ctx->final_used) {
        /* see comment about PTRDIFF_T comparison above */
        if (((PTRDIFF_T)out == (PTRDIFF_T)in)
            || is_partially_overlapping(out, in, b)) {
            EVPerr(EVP_F_EVP_DECRYPTUPDATE, EVP_R_PARTIALLY_OVERLAPPING);
            return 0;
        }
        memcpy(out, ctx->final, b);
        out += b;
        fix_len = 1;
    } else
        fix_len = 0;

    if (!evp_EncryptDecryptUpdate(ctx, out, outl, in, inl))
        return 0;

    /*
     * if we have 'decrypted' a multiple of block size, make sure we have a
     * copy of this last block
     */
    if (b > 1 && !ctx->buf_len) {
        *outl -= b;
        ctx->final_used = 1;
        memcpy(ctx->final, &out[*outl], b);
    } else
        ctx->final_used = 0;

    if (fix_len)
        *outl += b;

    return 1;
}

int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int ret;
    ret = EVP_DecryptFinal_ex(ctx, out, outl);
    return ret;
}

int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int i, n;
    unsigned int b;
    size_t soutl;
    int ret;
    int blocksize;

    /* Prevent accidental use of encryption context when decrypting */
    if (ctx->encrypt) {
        EVPerr(EVP_F_EVP_DECRYPTFINAL_EX, EVP_R_INVALID_OPERATION);
        return 0;
    }

    if (ctx->cipher == NULL) {
        EVPerr(EVP_F_EVP_DECRYPTFINAL_EX, EVP_R_NO_CIPHER_SET);
        return 0;
    }

    if (ctx->cipher->prov == NULL)
        goto legacy;

    blocksize = EVP_CIPHER_CTX_block_size(ctx);

    if (blocksize < 1 || ctx->cipher->cfinal == NULL) {
        EVPerr(EVP_F_EVP_DECRYPTFINAL_EX, EVP_R_FINAL_ERROR);
        return 0;
    }

    ret = ctx->cipher->cfinal(ctx->provctx, out, &soutl,
                              blocksize == 1 ? 0 : blocksize);

    if (ret) {
        if (soutl > INT_MAX) {
            EVPerr(EVP_F_EVP_DECRYPTFINAL_EX, EVP_R_FINAL_ERROR);
            return 0;
        }
        *outl = soutl;
    }

    return ret;

    /* TODO(3.0): Remove legacy code below */
 legacy:

    *outl = 0;
    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        i = ctx->cipher->do_cipher(ctx, out, NULL, 0);
        if (i < 0)
            return 0;
        else
            *outl = i;
        return 1;
    }

    b = ctx->cipher->block_size;
    if (ctx->flags & EVP_CIPH_NO_PADDING) {
        if (ctx->buf_len) {
            EVPerr(EVP_F_EVP_DECRYPTFINAL_EX,
                   EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH);
            return 0;
        }
        *outl = 0;
        return 1;
    }
    if (b > 1) {
        if (ctx->buf_len || !ctx->final_used) {
            EVPerr(EVP_F_EVP_DECRYPTFINAL_EX, EVP_R_WRONG_FINAL_BLOCK_LENGTH);
            return 0;
        }
        OPENSSL_assert(b <= sizeof(ctx->final));

        /*
         * The following assumes that the ciphertext has been authenticated.
         * Otherwise it provides a padding oracle.
         */
        n = ctx->final[b - 1];
        if (n == 0 || n > (int)b) {
            EVPerr(EVP_F_EVP_DECRYPTFINAL_EX, EVP_R_BAD_DECRYPT);
            return 0;
        }
        for (i = 0; i < n; i++) {
            if (ctx->final[--b] != n) {
                EVPerr(EVP_F_EVP_DECRYPTFINAL_EX, EVP_R_BAD_DECRYPT);
                return 0;
            }
        }
        n = ctx->cipher->block_size - n;
        for (i = 0; i < n; i++)
            out[i] = ctx->final[i];
        *outl = n;
    } else
        *outl = 0;
    return 1;
}

int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *c, int keylen)
{
    if (c->cipher->flags & EVP_CIPH_CUSTOM_KEY_LENGTH)
        return EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_SET_KEY_LENGTH, keylen, NULL);
    if (EVP_CIPHER_CTX_key_length(c) == keylen)
        return 1;
    if ((keylen > 0) && (c->cipher->flags & EVP_CIPH_VARIABLE_LENGTH)) {
        c->key_len = keylen;
        return 1;
    }
    EVPerr(EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH, EVP_R_INVALID_KEY_LENGTH);
    return 0;
}

int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int pad)
{
    if (pad)
        ctx->flags &= ~EVP_CIPH_NO_PADDING;
    else
        ctx->flags |= EVP_CIPH_NO_PADDING;

    if (ctx->cipher != NULL && ctx->cipher->prov != NULL) {
        OSSL_PARAM params[] = {
            OSSL_PARAM_int(OSSL_CIPHER_PARAM_PADDING, NULL),
            OSSL_PARAM_END
        };

        params[0].data = &pad;

        if (ctx->cipher->ctx_set_params == NULL) {
            EVPerr(EVP_F_EVP_CIPHER_CTX_SET_PADDING, EVP_R_CTRL_NOT_IMPLEMENTED);
            return 0;
        }

        if (!ctx->cipher->ctx_set_params(ctx->provctx, params))
            return 0;
    }

    return 1;
}

int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    int ret;

    if (!ctx->cipher) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL, EVP_R_NO_CIPHER_SET);
        return 0;
    }

    if (!ctx->cipher->ctrl) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL, EVP_R_CTRL_NOT_IMPLEMENTED);
        return 0;
    }

    ret = ctx->cipher->ctrl(ctx, type, arg, ptr);
    if (ret == -1) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL,
               EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED);
        return 0;
    }
    return ret;
}

#if !defined(FIPS_MODE)
/* TODO(3.0): No support for RAND yet in the FIPS module */
int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key)
{
    int kl;
    if (ctx->cipher->flags & EVP_CIPH_RAND_KEY)
        return EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_RAND_KEY, 0, key);
    kl = EVP_CIPHER_CTX_key_length(ctx);
    if (kl <= 0 || RAND_priv_bytes(key, kl) <= 0)
        return 0;
    return 1;
}
#endif

int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in)
{
    if ((in == NULL) || (in->cipher == NULL)) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_COPY, EVP_R_INPUT_NOT_INITIALIZED);
        return 0;
    }

    if (in->cipher->prov == NULL)
        goto legacy;

    if (in->cipher->dupctx == NULL) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_COPY, EVP_R_NOT_ABLE_TO_COPY_CTX);
        return 0;
    }

    EVP_CIPHER_CTX_reset(out);

    *out = *in;
    out->provctx = NULL;

    if (in->fetched_cipher != NULL && !EVP_CIPHER_up_ref(in->fetched_cipher)) {
        out->fetched_cipher = NULL;
        return 0;
    }

    out->provctx = in->cipher->dupctx(in->provctx);
    if (out->provctx == NULL) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_COPY, EVP_R_NOT_ABLE_TO_COPY_CTX);
        return 0;
    }

    return 1;

    /* TODO(3.0): Remove legacy code below */
 legacy:

#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODE)
    /* Make sure it's safe to copy a cipher context using an ENGINE */
    if (in->engine && !ENGINE_init(in->engine)) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_COPY, ERR_R_ENGINE_LIB);
        return 0;
    }
#endif

    EVP_CIPHER_CTX_reset(out);
    memcpy(out, in, sizeof(*out));

    if (in->cipher_data && in->cipher->ctx_size) {
        out->cipher_data = OPENSSL_malloc(in->cipher->ctx_size);
        if (out->cipher_data == NULL) {
            out->cipher = NULL;
            EVPerr(EVP_F_EVP_CIPHER_CTX_COPY, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(out->cipher_data, in->cipher_data, in->cipher->ctx_size);
    }

    if (in->cipher->flags & EVP_CIPH_CUSTOM_COPY)
        if (!in->cipher->ctrl((EVP_CIPHER_CTX *)in, EVP_CTRL_COPY, 0, out)) {
            out->cipher = NULL;
            EVPerr(EVP_F_EVP_CIPHER_CTX_COPY, EVP_R_INITIALIZATION_ERROR);
            return 0;
        }
    return 1;
}

static void *evp_cipher_from_dispatch(const OSSL_DISPATCH *fns,
                                      OSSL_PROVIDER *prov)
{
    EVP_CIPHER *cipher = NULL;
    int fnciphcnt = 0, fnctxcnt = 0;

    /*
     * The legacy NID is set by EVP_CIPHER_fetch() if the name exists in
     * the object database.
     */
    if ((cipher = EVP_CIPHER_meth_new(0, 0, 0)) == NULL)
        return NULL;

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_CIPHER_NEWCTX:
            if (cipher->newctx != NULL)
                break;
            cipher->newctx = OSSL_get_OP_cipher_newctx(fns);
            fnctxcnt++;
            break;
        case OSSL_FUNC_CIPHER_ENCRYPT_INIT:
            if (cipher->einit != NULL)
                break;
            cipher->einit = OSSL_get_OP_cipher_encrypt_init(fns);
            fnciphcnt++;
            break;
        case OSSL_FUNC_CIPHER_DECRYPT_INIT:
            if (cipher->dinit != NULL)
                break;
            cipher->dinit = OSSL_get_OP_cipher_decrypt_init(fns);
            fnciphcnt++;
            break;
        case OSSL_FUNC_CIPHER_UPDATE:
            if (cipher->cupdate != NULL)
                break;
            cipher->cupdate = OSSL_get_OP_cipher_update(fns);
            fnciphcnt++;
            break;
        case OSSL_FUNC_CIPHER_FINAL:
            if (cipher->cfinal != NULL)
                break;
            cipher->cfinal = OSSL_get_OP_cipher_final(fns);
            fnciphcnt++;
            break;
        case OSSL_FUNC_CIPHER_CIPHER:
            if (cipher->ccipher != NULL)
                break;
            cipher->ccipher = OSSL_get_OP_cipher_cipher(fns);
            break;
        case OSSL_FUNC_CIPHER_FREECTX:
            if (cipher->freectx != NULL)
                break;
            cipher->freectx = OSSL_get_OP_cipher_freectx(fns);
            fnctxcnt++;
            break;
        case OSSL_FUNC_CIPHER_DUPCTX:
            if (cipher->dupctx != NULL)
                break;
            cipher->dupctx = OSSL_get_OP_cipher_dupctx(fns);
            break;
        case OSSL_FUNC_CIPHER_KEY_LENGTH:
            if (cipher->key_length != NULL)
                break;
            cipher->key_length = OSSL_get_OP_cipher_key_length(fns);
            break;
        case OSSL_FUNC_CIPHER_IV_LENGTH:
            if (cipher->iv_length != NULL)
                break;
            cipher->iv_length = OSSL_get_OP_cipher_iv_length(fns);
            break;
        case OSSL_FUNC_CIPHER_BLOCK_SIZE:
            if (cipher->blocksize != NULL)
                break;
            cipher->blocksize = OSSL_get_OP_cipher_block_size(fns);
            break;
        case OSSL_FUNC_CIPHER_GET_PARAMS:
            if (cipher->get_params != NULL)
                break;
            cipher->get_params = OSSL_get_OP_cipher_get_params(fns);
            break;
        case OSSL_FUNC_CIPHER_CTX_GET_PARAMS:
            if (cipher->ctx_get_params != NULL)
                break;
            cipher->ctx_get_params = OSSL_get_OP_cipher_ctx_get_params(fns);
            break;
        case OSSL_FUNC_CIPHER_CTX_SET_PARAMS:
            if (cipher->ctx_set_params != NULL)
                break;
            cipher->ctx_set_params = OSSL_get_OP_cipher_ctx_set_params(fns);
            break;
        }
    }
    if ((fnciphcnt != 0 && fnciphcnt != 3 && fnciphcnt != 4)
            || (fnciphcnt == 0 && cipher->ccipher == NULL)
            || fnctxcnt != 2
            || cipher->blocksize == NULL
            || cipher->iv_length == NULL
            || cipher->key_length == NULL) {
        /*
         * In order to be a consistent set of functions we must have at least
         * a complete set of "encrypt" functions, or a complete set of "decrypt"
         * functions, or a single "cipher" function. In all cases we need a
         * complete set of context management functions, as well as the
         * blocksize, iv_length and key_length functions.
         */
        EVP_CIPHER_meth_free(cipher);
        EVPerr(EVP_F_EVP_CIPHER_FROM_DISPATCH, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        return NULL;
    }
    cipher->prov = prov;
    if (prov != NULL)
        ossl_provider_upref(prov);

    return cipher;
}

static int evp_cipher_up_ref(void *cipher)
{
    return EVP_CIPHER_up_ref(cipher);
}

static void evp_cipher_free(void *cipher)
{
    EVP_CIPHER_meth_free(cipher);
}

EVP_CIPHER *EVP_CIPHER_fetch(OPENSSL_CTX *ctx, const char *algorithm,
                             const char *properties)
{
    EVP_CIPHER *cipher =
        evp_generic_fetch(ctx, OSSL_OP_CIPHER, algorithm, properties,
                          evp_cipher_from_dispatch, evp_cipher_up_ref,
                          evp_cipher_free);

#ifndef FIPS_MODE
    /* TODO(3.x) get rid of the need for legacy NIDs */
    if (cipher != NULL) {
        /*
         * FIPS module note: since internal fetches will be entirely
         * provider based, we know that none of its code depends on legacy
         * NIDs or any functionality that use them.
         */
        cipher->nid = OBJ_sn2nid(algorithm);
    }
#endif

    return cipher;
}
