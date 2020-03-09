/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include "crypto/evp.h"
#include "internal/provider.h"
#include "evp_local.h"
#include "legacy_meth.h"

int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *ctx)
{
    if (ctx == NULL)
        return 1;

#if !defined(FIPS_MODE)
    {
        int ret = 0;

        if (legacy_evp_cipher_ctx_reset(ctx, &ret))
            return ret;
    }
#endif

    if (ctx->provctx != NULL) {
        if (ctx->cipher->freectx != NULL)
            ctx->cipher->freectx(ctx->provctx);
        ctx->provctx = NULL;
    }
    if (ctx->fetched_cipher != NULL)
        EVP_CIPHER_free(ctx->fetched_cipher);
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

#if !defined(FIPS_MODE)
    {
        int ret = 0;

        if (legacy_evp_cipher_init_ex(ctx, cipher, impl, key, iv, enc, &ret))
            return ret;
    }
#endif

    /* Ensure a context left lying around from last time is cleared */
    if (cipher != NULL && ctx->cipher != NULL) {
        unsigned long flags = ctx->flags;

        EVP_CIPHER_CTX_reset(ctx);
        /* Restore encrypt and flags */
        ctx->encrypt = enc;
        ctx->flags = flags;
    }

    if (cipher == NULL)
        cipher = ctx->cipher;

    if (cipher->prov == NULL) {
#ifdef FIPS_MODE
        /* We only do explicit fetches inside the FIPS module */
        EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_INITIALIZATION_ERROR);
        return 0;
#else
        EVP_CIPHER *provciph =
            EVP_CIPHER_fetch(NULL,
                             cipher->nid == NID_undef ? "NULL"
                                                      : OBJ_nid2sn(cipher->nid),
                             "");

        if (provciph == NULL) {
            EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_INITIALIZATION_ERROR);
            return 0;
        }
        cipher = provciph;
        EVP_CIPHER_free(ctx->fetched_cipher);
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

int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl)
{
    int ret = 0;
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

#if !defined(FIPS_MODE)
    if (legacy_evp_encrypt_update(ctx, out, outl, in, inl, &ret))
        return ret;
#endif

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
}

int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    return EVP_EncryptFinal_ex(ctx, out, outl);
}

int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int ret = 0;
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

#if !defined(FIPS_MODE)
    if (legacy_evp_encrypt_final_ex(ctx, out, outl, &ret))
        return ret;
#endif

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
}

int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl)
{
    int ret = 0;
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

#if !defined(FIPS_MODE)
    if (legacy_evp_decrypt_update(ctx, out, outl, in, inl, &ret))
        return ret;
#endif

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
}

int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    return EVP_DecryptFinal_ex(ctx, out, outl);
}

int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    size_t soutl;
    int ret = 0;
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

#if !defined(FIPS_MODE)
    if (legacy_evp_decrypt_final_ex(ctx, out, outl, &ret))
        return ret;
#endif

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
}

int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *c, int keylen)
{
    int ret = 0;
#if !defined(FIPS_MODE)
    if (legacy_evp_cipher_ctx_set_key_length(c, keylen, &ret))
        return ret;
#endif
    {
        OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
        size_t len = keylen;

        if (EVP_CIPHER_CTX_key_length(c) == keylen)
            return 1;

        /* Check the cipher actually understands this parameter */
        if (OSSL_PARAM_locate_const(EVP_CIPHER_settable_ctx_params(c->cipher),
                                    OSSL_CIPHER_PARAM_KEYLEN) == NULL)
            return 0;

        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &len);
        ret = evp_do_ciph_ctx_setparams(c->cipher, c->provctx, params);

        return ret > 0 ? 1 : 0;
    }
}

int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int pad)
{
    int ok;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    unsigned int pd = pad;

    if (pad)
        ctx->flags &= ~EVP_CIPH_NO_PADDING;
    else
        ctx->flags |= EVP_CIPH_NO_PADDING;

    params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, &pd);
    ok = evp_do_ciph_ctx_setparams(ctx->cipher, ctx->provctx, params);

    return ok != 0;
}

int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    int ret = EVP_CTRL_RET_UNSUPPORTED;
    int set_params = 1;
    size_t sz = arg;
    unsigned int i;
    OSSL_PARAM params[4] = {
        OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END
    };

    if (ctx == NULL || ctx->cipher == NULL) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL, EVP_R_NO_CIPHER_SET);
        return 0;
    }
#if !defined(FIPS_MODE)
    if (legacy_evp_cipher_ctx_ctrl(ctx, type, arg, ptr, &ret))
        return ret;
#endif
    switch (type) {
    case EVP_CTRL_SET_KEY_LENGTH:
        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &sz);
        break;
    case EVP_CTRL_RAND_KEY:      /* Used by DES */
        set_params = 0;
        params[0] =
            OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_RANDOM_KEY,
                                              ptr, sz);
        break;

    case EVP_CTRL_INIT:
        /*
         * TODO(3.0) EVP_CTRL_INIT is purely legacy, no provider counterpart
         * As a matter of fact, this should be dead code, but some caller
         * might still do a direct control call with this command, so...
         * Legacy methods return 1 except for exceptional circumstances, so
         * we do the same here to not be disruptive.
         */
        return 1;
    case EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS: /* Used by DASYNC */
    default:
        goto end;
    case EVP_CTRL_GET_IV:
        set_params = 0;
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_IV,
                                                      ptr, sz);
        break;
    case EVP_CTRL_AEAD_SET_IVLEN:
        if (arg < 0)
            return 0;
        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &sz);
        break;
    case EVP_CTRL_AEAD_SET_IV_FIXED:
        params[0] = OSSL_PARAM_construct_octet_string(
                        OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, ptr, sz);
        break;
    case EVP_CTRL_GCM_IV_GEN:
        set_params = 0;
        if (arg < 0)
            sz = 0; /* special case that uses the iv length */
        params[0] = OSSL_PARAM_construct_octet_string(
                        OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN, ptr, sz);
        break;
    case EVP_CTRL_GCM_SET_IV_INV:
        if (arg < 0)
            return 0;
        params[0] = OSSL_PARAM_construct_octet_string(
                        OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV, ptr, sz);
        break;
    case EVP_CTRL_GET_RC5_ROUNDS:
        set_params = 0; /* Fall thru */
    case EVP_CTRL_SET_RC5_ROUNDS:
        if (arg < 0)
            return 0;
        i = (unsigned int)arg;
        params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_ROUNDS, &i);
        break;
    case EVP_CTRL_SET_SPEED:
        if (arg < 0)
            return 0;
        i = (unsigned int)arg;
        params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_SPEED, &i);
        break;
    case EVP_CTRL_AEAD_GET_TAG:
        set_params = 0; /* Fall thru */
    case EVP_CTRL_AEAD_SET_TAG:
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                      ptr, sz);
        break;
    case EVP_CTRL_AEAD_TLS1_AAD:
        /* This one does a set and a get - since it returns a size */
        params[0] =
            OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD,
                                              ptr, sz);
        ret = evp_do_ciph_ctx_setparams(ctx->cipher, ctx->provctx, params);
        if (ret <= 0)
            goto end;
        params[0] =
            OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, &sz);
        ret = evp_do_ciph_ctx_getparams(ctx->cipher, ctx->provctx, params);
        if (ret <= 0)
            goto end;
        return sz;
#ifndef OPENSSL_NO_RC2
    case EVP_CTRL_GET_RC2_KEY_BITS:
        set_params = 0; /* Fall thru */
    case EVP_CTRL_SET_RC2_KEY_BITS:
        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_RC2_KEYBITS, &sz);
        break;
#endif /* OPENSSL_NO_RC2 */
#if !defined(OPENSSL_NO_MULTIBLOCK)
    case EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE:
        params[0] = OSSL_PARAM_construct_size_t(
                OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT, &sz);
        ret = evp_do_ciph_ctx_setparams(ctx->cipher, ctx->provctx, params);
        if (ret <= 0)
            return 0;

        params[0] = OSSL_PARAM_construct_size_t(
                OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE, &sz);
        params[1] = OSSL_PARAM_construct_end();
        ret = evp_do_ciph_ctx_getparams(ctx->cipher, ctx->provctx, params);
        if (ret <= 0)
            return 0;
        return sz;
    case EVP_CTRL_TLS1_1_MULTIBLOCK_AAD: {
        EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM *p =
            (EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM *)ptr;

        if (arg < (int)sizeof(EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM))
            return 0;

        params[0] = OSSL_PARAM_construct_octet_string(
                OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD, (void*)p->inp, p->len);
        params[1] = OSSL_PARAM_construct_uint(
                OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE, &p->interleave);
        ret = evp_do_ciph_ctx_setparams(ctx->cipher, ctx->provctx, params);
        if (ret <= 0)
            return ret;
        /* Retrieve the return values changed by the set */
        params[0] = OSSL_PARAM_construct_size_t(
                OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN, &sz);
        params[1] = OSSL_PARAM_construct_uint(
                OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE, &p->interleave);
        params[2] = OSSL_PARAM_construct_end();
        ret = evp_do_ciph_ctx_getparams(ctx->cipher, ctx->provctx, params);
        if (ret <= 0)
            return 0;
        return sz;
    }
    case EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT: {
        EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM *p =
            (EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM *)ptr;

        params[0] = OSSL_PARAM_construct_octet_string(
                        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC, p->out, p->len);

        params[1] = OSSL_PARAM_construct_octet_string(
                OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_IN, (void*)p->inp,
                p->len);
        params[2] = OSSL_PARAM_construct_uint(
                OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE, &p->interleave);
        ret = evp_do_ciph_ctx_setparams(ctx->cipher, ctx->provctx, params);
        if (ret <= 0)
            return ret;
        params[0] = OSSL_PARAM_construct_size_t(
                        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_LEN, &sz);
        params[1] = OSSL_PARAM_construct_end();
        ret = evp_do_ciph_ctx_getparams(ctx->cipher, ctx->provctx, params);
        if (ret <= 0)
            return 0;
        return sz;
    }
#endif /* OPENSSL_NO_MULTIBLOCK */
    case EVP_CTRL_AEAD_SET_MAC_KEY:
        if (arg < 0)
            return -1;
        params[0] = OSSL_PARAM_construct_octet_string(
                OSSL_CIPHER_PARAM_AEAD_MAC_KEY, ptr, sz);
        break;
    }

    if (set_params)
        ret = evp_do_ciph_ctx_setparams(ctx->cipher, ctx->provctx, params);
    else
        ret = evp_do_ciph_ctx_getparams(ctx->cipher, ctx->provctx, params);
end:
    if (ret == EVP_CTRL_RET_UNSUPPORTED) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL,
               EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED);
        return 0;
    }
    return ret;
}

int EVP_CIPHER_get_params(EVP_CIPHER *cipher, OSSL_PARAM params[])
{
    if (cipher != NULL && cipher->get_params != NULL)
        return cipher->get_params(params);
    return 0;
}

int EVP_CIPHER_CTX_set_params(EVP_CIPHER_CTX *ctx, const OSSL_PARAM params[])
{
    if (ctx->cipher != NULL && ctx->cipher->set_ctx_params != NULL)
        return ctx->cipher->set_ctx_params(ctx->provctx, params);
    return 0;
}

int EVP_CIPHER_CTX_get_params(EVP_CIPHER_CTX *ctx, OSSL_PARAM params[])
{
    if (ctx->cipher != NULL && ctx->cipher->get_ctx_params != NULL)
        return ctx->cipher->get_ctx_params(ctx->provctx, params);
    return 0;
}

const OSSL_PARAM *EVP_CIPHER_gettable_params(const EVP_CIPHER *cipher)
{
    if (cipher != NULL && cipher->gettable_params != NULL)
        return cipher->gettable_params();
    return NULL;
}

const OSSL_PARAM *EVP_CIPHER_settable_ctx_params(const EVP_CIPHER *cipher)
{
    if (cipher != NULL && cipher->settable_ctx_params != NULL)
        return cipher->settable_ctx_params();
    return NULL;
}

const OSSL_PARAM *EVP_CIPHER_gettable_ctx_params(const EVP_CIPHER *cipher)
{
    if (cipher != NULL && cipher->gettable_ctx_params != NULL)
        return cipher->gettable_ctx_params();
    return NULL;
}

int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key)
{
    if (ctx->cipher->flags & EVP_CIPH_RAND_KEY)
        return EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_RAND_KEY, 0, key);

#ifdef FIPS_MODE
    return 0;
#else
    {
        int kl;

        kl = EVP_CIPHER_CTX_key_length(ctx);
        if (kl <= 0 || RAND_priv_bytes(key, kl) <= 0)
            return 0;
        return 1;
    }
#endif /* FIPS_MODE */
}

int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in)
{
    if ((in == NULL) || (in->cipher == NULL)) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_COPY, EVP_R_INPUT_NOT_INITIALIZED);
        return 0;
    }

#if !defined(FIPS_MODE)
    {
        int ret = 0;

        if (legacy_evp_cipher_ctx_copy(out, in, &ret))
            return ret;
    }
#endif

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
}

EVP_CIPHER *evp_cipher_new(void)
{
    EVP_CIPHER *cipher = OPENSSL_zalloc(sizeof(EVP_CIPHER));

    if (cipher != NULL) {
        cipher->lock = CRYPTO_THREAD_lock_new();
        if (cipher->lock == NULL) {
            OPENSSL_free(cipher);
            return NULL;
        }
        cipher->refcnt = 1;
    }
    return cipher;
}

static void *evp_cipher_from_dispatch(const int name_id,
                                      const OSSL_DISPATCH *fns,
                                      OSSL_PROVIDER *prov)
{
    EVP_CIPHER *cipher = NULL;
    int fnciphcnt = 0, fnctxcnt = 0;

    if ((cipher = evp_cipher_new()) == NULL) {
        EVPerr(0, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

#ifndef FIPS_MODE
    /* TODO(3.x) get rid of the need for legacy NIDs */
    cipher->nid = NID_undef;
    evp_names_do_all(prov, name_id, legacy_evp_cipher_set_nid, &cipher->nid);
    if (cipher->nid == -1) {
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        EVP_CIPHER_free(cipher);
        return NULL;
    }
#endif

    cipher->name_id = name_id;

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
        case OSSL_FUNC_CIPHER_GET_PARAMS:
            if (cipher->get_params != NULL)
                break;
            cipher->get_params = OSSL_get_OP_cipher_get_params(fns);
            break;
        case OSSL_FUNC_CIPHER_GET_CTX_PARAMS:
            if (cipher->get_ctx_params != NULL)
                break;
            cipher->get_ctx_params = OSSL_get_OP_cipher_get_ctx_params(fns);
            break;
        case OSSL_FUNC_CIPHER_SET_CTX_PARAMS:
            if (cipher->set_ctx_params != NULL)
                break;
            cipher->set_ctx_params = OSSL_get_OP_cipher_set_ctx_params(fns);
            break;
        case OSSL_FUNC_CIPHER_GETTABLE_PARAMS:
            if (cipher->gettable_params != NULL)
                break;
            cipher->gettable_params = OSSL_get_OP_cipher_gettable_params(fns);
            break;
        case OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS:
            if (cipher->gettable_ctx_params != NULL)
                break;
            cipher->gettable_ctx_params =
                OSSL_get_OP_cipher_gettable_ctx_params(fns);
            break;
        case OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS:
            if (cipher->settable_ctx_params != NULL)
                break;
            cipher->settable_ctx_params =
                OSSL_get_OP_cipher_settable_ctx_params(fns);
            break;
        }
    }
    if ((fnciphcnt != 0 && fnciphcnt != 3 && fnciphcnt != 4)
            || (fnciphcnt == 0 && cipher->ccipher == NULL)
            || fnctxcnt != 2) {
        /*
         * In order to be a consistent set of functions we must have at least
         * a complete set of "encrypt" functions, or a complete set of "decrypt"
         * functions, or a single "cipher" function. In all cases we need both
         * the "newctx" and "freectx" functions.
         */
        EVP_CIPHER_free(cipher);
        EVPerr(EVP_F_EVP_CIPHER_FROM_DISPATCH, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        return NULL;
    }
    cipher->prov = prov;
    if (prov != NULL)
        ossl_provider_up_ref(prov);

    return cipher;
}

static int evp_cipher_up_ref(void *cipher)
{
    return EVP_CIPHER_up_ref(cipher);
}

static void evp_cipher_free(void *cipher)
{
    EVP_CIPHER_free(cipher);
}

EVP_CIPHER *EVP_CIPHER_fetch(OPENSSL_CTX *ctx, const char *algorithm,
                             const char *properties)
{
    EVP_CIPHER *cipher =
        evp_generic_fetch(ctx, OSSL_OP_CIPHER, algorithm, properties,
                          evp_cipher_from_dispatch, evp_cipher_up_ref,
                          evp_cipher_free);

    if (cipher != NULL && !evp_cipher_cache_constants(cipher)) {
        EVP_CIPHER_free(cipher);
        cipher = NULL;
    }
    return cipher;
}

int EVP_CIPHER_up_ref(EVP_CIPHER *cipher)
{
    int ref = 0;

    CRYPTO_UP_REF(&cipher->refcnt, &ref, cipher->lock);
    return 1;
}

void EVP_CIPHER_free(EVP_CIPHER *cipher)
{
    int i;

    if (cipher == NULL)
        return;

    CRYPTO_DOWN_REF(&cipher->refcnt, &i, cipher->lock);
    if (i > 0)
        return;
    ossl_provider_free(cipher->prov);
    CRYPTO_THREAD_lock_free(cipher->lock);
    OPENSSL_free(cipher);
}

void EVP_CIPHER_do_all_provided(OPENSSL_CTX *libctx,
                                void (*fn)(EVP_CIPHER *mac, void *arg),
                                void *arg)
{
    evp_generic_do_all(libctx, OSSL_OP_CIPHER,
                       (void (*)(void *, void *))fn, arg,
                       evp_cipher_from_dispatch, evp_cipher_free);
}
