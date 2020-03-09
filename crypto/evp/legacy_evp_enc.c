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
#include <openssl/engine.h>
#include "crypto/evp.h"
#include "evp_local.h"
#include "legacy_meth.h"

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

static int evp_EncryptDecryptUpdate(EVP_CIPHER_CTX *ctx,
                                    unsigned char *out, int *outl,
                                    const unsigned char *in, int inl);

int legacy_evp_cipher_ctx_reset(EVP_CIPHER_CTX *ctx, int *ret)
{
    if (ctx->cipher == NULL || ctx->cipher->prov == NULL) {
        if (ctx->cipher != NULL) {
            if (ctx->cipher->cleanup && !ctx->cipher->cleanup(ctx)) {
                *ret = 0;
                goto end;
            }
            /* Cleanse cipher context data */
            if (ctx->cipher_data && ctx->cipher->ctx_size)
                OPENSSL_cleanse(ctx->cipher_data, ctx->cipher->ctx_size);
        }
        OPENSSL_free(ctx->cipher_data);
# if !defined(OPENSSL_NO_ENGINE)
        ENGINE_finish(ctx->engine);
# endif
        memset(ctx, 0, sizeof(*ctx));
        *ret = 1;
end:
        return 1;
    }
    return 0;
}

int legacy_evp_cipher_init_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                              ENGINE *impl, const unsigned char *key,
                              const unsigned char *iv, int enc, int *ret)
{
    const EVP_CIPHER *tmpcipher;

#if !defined(OPENSSL_NO_ENGINE)
    ENGINE *tmpimpl = NULL;
/*
 * Whether it's nice or not, "Inits" can be used on "Final"'d contexts so
 * this context may already have an ENGINE! Try to avoid releasing the
 * previous handle, re-querying for an ENGINE, and having a
 * reinitialisation, when it may all be unnecessary.
 */
    if (ctx->engine != NULL
        && ctx->cipher != NULL
        && (cipher == NULL || cipher->nid == ctx->cipher->nid))
        goto skip_to_init;

    /* Ask if an ENGINE is reserved for this job */
    if (cipher != NULL && impl == NULL)
        tmpimpl = ENGINE_get_cipher_engine(cipher->nid);
#endif

    /*
     * If there are engines involved then we should use legacy handling for now.
     */
    if (ctx->engine != NULL
#if !defined(OPENSSL_NO_ENGINE)
        || tmpimpl != NULL
#endif
        || impl != NULL) {
            if (ctx->cipher == ctx->fetched_cipher)
                ctx->cipher = NULL;
            EVP_CIPHER_free(ctx->fetched_cipher);
            ctx->fetched_cipher = NULL;
            goto legacy;
    }
    tmpcipher = (cipher == NULL) ? ctx->cipher : cipher;

    if (tmpcipher->prov == NULL) {
        switch(tmpcipher->nid) {
        case NID_undef:
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
        case NID_aes_128_xts:
        case NID_aes_256_xts:
        case NID_aes_256_ocb:
        case NID_aes_192_ocb:
        case NID_aes_128_ocb:
        case NID_aes_256_gcm:
        case NID_aes_192_gcm:
        case NID_aes_128_gcm:
        case NID_aes_256_siv:
        case NID_aes_192_siv:
        case NID_aes_128_siv:
        case NID_aes_256_cbc_hmac_sha256:
        case NID_aes_128_cbc_hmac_sha256:
        case NID_aes_256_cbc_hmac_sha1:
        case NID_aes_128_cbc_hmac_sha1:
        case NID_id_aes256_wrap:
        case NID_id_aes256_wrap_pad:
        case NID_id_aes192_wrap:
        case NID_id_aes192_wrap_pad:
        case NID_id_aes128_wrap:
        case NID_id_aes128_wrap_pad:
        case NID_aria_256_gcm:
        case NID_aria_192_gcm:
        case NID_aria_128_gcm:
        case NID_aes_256_ccm:
        case NID_aes_192_ccm:
        case NID_aes_128_ccm:
        case NID_aria_256_ccm:
        case NID_aria_192_ccm:
        case NID_aria_128_ccm:
        case NID_aria_256_ecb:
        case NID_aria_192_ecb:
        case NID_aria_128_ecb:
        case NID_aria_256_cbc:
        case NID_aria_192_cbc:
        case NID_aria_128_cbc:
        case NID_aria_256_ofb128:
        case NID_aria_192_ofb128:
        case NID_aria_128_ofb128:
        case NID_aria_256_cfb128:
        case NID_aria_192_cfb128:
        case NID_aria_128_cfb128:
        case NID_aria_256_cfb1:
        case NID_aria_192_cfb1:
        case NID_aria_128_cfb1:
        case NID_aria_256_cfb8:
        case NID_aria_192_cfb8:
        case NID_aria_128_cfb8:
        case NID_aria_256_ctr:
        case NID_aria_192_ctr:
        case NID_aria_128_ctr:
        case NID_camellia_256_ecb:
        case NID_camellia_192_ecb:
        case NID_camellia_128_ecb:
        case NID_camellia_256_cbc:
        case NID_camellia_192_cbc:
        case NID_camellia_128_cbc:
        case NID_camellia_256_ofb128:
        case NID_camellia_192_ofb128:
        case NID_camellia_128_ofb128:
        case NID_camellia_256_cfb128:
        case NID_camellia_192_cfb128:
        case NID_camellia_128_cfb128:
        case NID_camellia_256_cfb1:
        case NID_camellia_192_cfb1:
        case NID_camellia_128_cfb1:
        case NID_camellia_256_cfb8:
        case NID_camellia_192_cfb8:
        case NID_camellia_128_cfb8:
        case NID_camellia_256_ctr:
        case NID_camellia_192_ctr:
        case NID_camellia_128_ctr:
        case NID_des_ede3_cbc:
        case NID_des_ede3_ecb:
        case NID_des_ede3_ofb64:
        case NID_des_ede3_cfb64:
        case NID_des_ede3_cfb8:
        case NID_des_ede3_cfb1:
        case NID_des_ede_cbc:
        case NID_des_ede_ecb:
        case NID_des_ede_ofb64:
        case NID_des_ede_cfb64:
        case NID_desx_cbc:
        case NID_des_cbc:
        case NID_des_ecb:
        case NID_des_cfb1:
        case NID_des_cfb8:
        case NID_des_cfb64:
        case NID_des_ofb64:
        case NID_id_smime_alg_CMS3DESwrap:
        case NID_bf_cbc:
        case NID_bf_ecb:
        case NID_bf_cfb64:
        case NID_bf_ofb64:
        case NID_idea_cbc:
        case NID_idea_ecb:
        case NID_idea_cfb64:
        case NID_idea_ofb64:
        case NID_cast5_cbc:
        case NID_cast5_ecb:
        case NID_cast5_cfb64:
        case NID_cast5_ofb64:
        case NID_seed_cbc:
        case NID_seed_ecb:
        case NID_seed_cfb128:
        case NID_seed_ofb128:
        case NID_sm4_cbc:
        case NID_sm4_ecb:
        case NID_sm4_ctr:
        case NID_sm4_cfb128:
        case NID_sm4_ofb128:
        case NID_rc4:
        case NID_rc4_40:
        case NID_rc5_cbc:
        case NID_rc5_ecb:
        case NID_rc5_cfb64:
        case NID_rc5_ofb64:
        case NID_rc2_cbc:
        case NID_rc2_40_cbc:
        case NID_rc2_64_cbc:
        case NID_rc2_cfb64:
        case NID_rc2_ofb64:
        case NID_chacha20:
        case NID_chacha20_poly1305:
        case NID_rc4_hmac_md5:
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
    return 0; /* Exit and Run non legacy code */
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
#if !defined(OPENSSL_NO_ENGINE)
        if (impl != NULL) {
            if (!ENGINE_init(impl)) {
                EVPerr(0, EVP_R_INITIALIZATION_ERROR);
                goto err;
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
                EVPerr(0, EVP_R_INITIALIZATION_ERROR);
                goto err;
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
                EVPerr(0, ERR_R_MALLOC_FAILURE);
                goto err;
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
                EVPerr(0, EVP_R_INITIALIZATION_ERROR);
                goto err;
            }
        }
    }
#if !defined(OPENSSL_NO_ENGINE)
skip_to_init:
#endif
    if (ctx->cipher == NULL)
        goto err;

    /* we assume block size is a power of 2 in *cryptUpdate */
    OPENSSL_assert(ctx->cipher->block_size == 1
                   || ctx->cipher->block_size == 8
                   || ctx->cipher->block_size == 16);

    if (!(ctx->flags & EVP_CIPHER_CTX_FLAG_WRAP_ALLOW)
        && EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_WRAP_MODE) {
        EVPerr(0, EVP_R_WRAP_MODE_NOT_ALLOWED);
        goto err;
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
            goto err;
        }
    }

    if (key || (ctx->cipher->flags & EVP_CIPH_ALWAYS_CALL_INIT)) {
        if (!ctx->cipher->init(ctx, key, iv, enc))
            goto err;
    }
    ctx->buf_len = 0;
    ctx->final_used = 0;
    ctx->block_mask = ctx->cipher->block_size - 1;

    *ret = 1;
    return 1;
err:
    *ret = 0;
    return 1;
}

int legacy_evp_encrypt_update(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              int *outl, const unsigned char *in, int inl,
                              int *ret)
{
    if (ctx->cipher->prov != NULL)
        return 0;
    *ret = evp_EncryptDecryptUpdate(ctx, out, outl, in, inl);
    return 1;
}

int legacy_evp_encrypt_final_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                int *outl, int *res)
{
    int n, ret = 0;
    unsigned int i, b, bl;

    if (ctx->cipher->prov != NULL)
        return 0; /* return and run non legacy case */

    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        ret = ctx->cipher->do_cipher(ctx, out, NULL, 0);
        if (ret < 0)
            goto err;
        else
            *outl = ret;
        goto end;
    }

    b = ctx->cipher->block_size;
    OPENSSL_assert(b <= sizeof(ctx->buf));
    if (b == 1) {
        *outl = 0;
        goto end;
    }
    bl = ctx->buf_len;
    if (ctx->flags & EVP_CIPH_NO_PADDING) {
        if (bl) {
            EVPerr(0, EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH);
            return 0;
        }
        *outl = 0;
        goto end;
    }

    n = b - bl;
    for (i = bl; i < b; i++)
        ctx->buf[i] = n;
    ret = ctx->cipher->do_cipher(ctx, out, ctx->buf, b);
    if (ret)
        *outl = b;
    *res = ret;
    return 1;
err:
    *res = 0;
    return 1;
end:
    *res = 1;
    return 1;
}

int legacy_evp_decrypt_update(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                              const unsigned char *in, int inl, int *ret)
{
    int fix_len, cmpl = inl;
    unsigned int b;

    if (ctx->cipher->prov != NULL)
        return 0;

    b = ctx->cipher->block_size;

    if (EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS))
        cmpl = (cmpl + 7) / 8;

    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        if (b == 1 && is_partially_overlapping(out, in, cmpl)) {
            EVPerr(0, EVP_R_PARTIALLY_OVERLAPPING);
            goto err;
        }

        fix_len = ctx->cipher->do_cipher(ctx, out, in, inl);
        if (fix_len < 0) {
            *outl = 0;
            goto err;
        } else
            *outl = fix_len;
        goto end;
    }

    if (inl <= 0) {
        *outl = 0;
         *ret = (inl == 0);
         return 1;
    }

    if (ctx->flags & EVP_CIPH_NO_PADDING) {
        *ret = evp_EncryptDecryptUpdate(ctx, out, outl, in, inl);
        return 1;
    }

    OPENSSL_assert(b <= sizeof(ctx->final));

    if (ctx->final_used) {
        /* see comment about PTRDIFF_T comparison above */
        if (((PTRDIFF_T)out == (PTRDIFF_T)in)
            || is_partially_overlapping(out, in, b)) {
            EVPerr(0, EVP_R_PARTIALLY_OVERLAPPING);
            return 0;
        }
        memcpy(out, ctx->final, b);
        out += b;
        fix_len = 1;
    } else
        fix_len = 0;

    if (!evp_EncryptDecryptUpdate(ctx, out, outl, in, inl))
        goto err;

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
end:
    *ret = 1;
    return 1;
err:
    *ret = 0;
    return 1;
}

int legacy_evp_decrypt_final_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                int *outl, int *ret)
{
    int i, n;
    unsigned int b;

    if (ctx->cipher->prov != NULL)
        return 0;

    *outl = 0;
    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        i = ctx->cipher->do_cipher(ctx, out, NULL, 0);
        if (i < 0)
            goto err;
        else
            *outl = i;
        goto end;
    }

    b = ctx->cipher->block_size;
    if (ctx->flags & EVP_CIPH_NO_PADDING) {
        if (ctx->buf_len) {
            EVPerr(0, EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH);
            goto err;
        }
        *outl = 0;
        goto end;
    }
    if (b > 1) {
        if (ctx->buf_len || !ctx->final_used) {
            EVPerr(0, EVP_R_WRONG_FINAL_BLOCK_LENGTH);
            goto err;
        }
        OPENSSL_assert(b <= sizeof(ctx->final));

        /*
         * The following assumes that the ciphertext has been authenticated.
         * Otherwise it provides a padding oracle.
         */
        n = ctx->final[b - 1];
        if (n == 0 || n > (int)b) {
            EVPerr(0, EVP_R_BAD_DECRYPT);
            goto err;
        }
        for (i = 0; i < n; i++) {
            if (ctx->final[--b] != n) {
                EVPerr(0, EVP_R_BAD_DECRYPT);
                goto err;
            }
        }
        n = ctx->cipher->block_size - n;
        for (i = 0; i < n; i++)
            out[i] = ctx->final[i];
        *outl = n;
    } else
        *outl = 0;
end:
    *ret = 1;
    return 1;
err:
    *ret = 0;
    return 1;
}

int legacy_evp_cipher_ctx_set_key_length(EVP_CIPHER_CTX *c, int keylen,
                                         int *ret)
{
    if (c->cipher->prov != NULL)
        return 0;

    /*
     * Note there have never been any built-in ciphers that define this flag
     * since it was first introduced.
     */
    if (c->cipher->flags & EVP_CIPH_CUSTOM_KEY_LENGTH) {
        *ret = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_SET_KEY_LENGTH, keylen, NULL);
        return 1;
    }
    if (EVP_CIPHER_CTX_key_length(c) == keylen)
        goto end;
    if ((keylen > 0) && (c->cipher->flags & EVP_CIPH_VARIABLE_LENGTH)) {
        c->key_len = keylen;
        goto end;
    }
    EVPerr(0, EVP_R_INVALID_KEY_LENGTH);
    *ret = 0;
    return 1;
end:
    *ret = 1;
    return 1;
}

int legacy_evp_cipher_ctx_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                               void *ptr, int *ret)
{
    int res;

    if (ctx->cipher->prov != NULL)
        return 0;

    if (ctx->cipher->ctrl == NULL) {
        EVPerr(0, EVP_R_CTRL_NOT_IMPLEMENTED);
        goto err;
    }

    res = ctx->cipher->ctrl(ctx, type, arg, ptr);
    if (res == EVP_CTRL_RET_UNSUPPORTED) {
        EVPerr(0, EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED);
        goto err;
    }
    *ret = res;
    return 1;
err:
    *ret = 0;
    return 1;
}

int legacy_evp_cipher_ctx_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in,
                               int *ret)
{
    if (in->cipher->prov != NULL)
        return 0;

#if !defined(OPENSSL_NO_ENGINE)
    /* Make sure it's safe to copy a cipher context using an ENGINE */
    if (in->engine && !ENGINE_init(in->engine)) {
        EVPerr(0, ERR_R_ENGINE_LIB);
        goto err;
    }
#endif
    EVP_CIPHER_CTX_reset(out);
    memcpy(out, in, sizeof(*out));

    if (in->cipher_data && in->cipher->ctx_size) {
        out->cipher_data = OPENSSL_malloc(in->cipher->ctx_size);
        if (out->cipher_data == NULL) {
            out->cipher = NULL;
            EVPerr(0, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memcpy(out->cipher_data, in->cipher_data, in->cipher->ctx_size);
    }

    if (in->cipher->flags & EVP_CIPH_CUSTOM_COPY)
        if (!in->cipher->ctrl((EVP_CIPHER_CTX *)in, EVP_CTRL_COPY, 0, out)) {
            out->cipher = NULL;
            EVPerr(0, EVP_R_INITIALIZATION_ERROR);
            goto err;
        }
    *ret = 1;
    return 1;
err:
    *ret = 0;
    return 1;
}

/*
 * FIPS module note: since internal fetches will be entirely
 * provider based, we know that none of its code depends on legacy
 * NIDs or any functionality that use them.
 */
/* TODO(3.x) get rid of the need for legacy NIDs */
void legacy_evp_cipher_set_nid(const char *name, void *vlegacy_nid)
{
    int nid;
    int *legacy_nid = vlegacy_nid;
    /*
     * We use lowest level function to get the associated method, because
     * higher level functions such as EVP_get_cipherbyname() have changed
     * to look at providers too.
     */
    const void *legacy_method = OBJ_NAME_get(name, OBJ_NAME_TYPE_CIPHER_METH);

    if (*legacy_nid == -1)       /* We found a clash already */
        return;
    if (legacy_method == NULL)
        return;
    nid = EVP_CIPHER_nid(legacy_method);
    if (*legacy_nid != NID_undef && *legacy_nid != nid) {
        *legacy_nid = -1;
        return;
    }
    *legacy_nid = nid;
}

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
            EVPerr(0, EVP_R_PARTIALLY_OVERLAPPING);
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
        EVPerr(0, EVP_R_PARTIALLY_OVERLAPPING);
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

