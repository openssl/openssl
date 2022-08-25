/*
 * Copyright 1995-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * EVP _meth_ APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"
#include "internal/sizes.h"

#include <stdio.h>
#include <string.h>
#include "internal/cryptlib.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include "crypto/evp.h"
#include "crypto/context.h"
#include "crypto/cryptlib.h"
#include "internal/provider.h"
#include "evp_local.h"

#if !defined(FIPS_MODULE)
# include "crypto/asn1.h"

int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    return evp_cipher_param_to_asn1_ex(c, type, NULL);
}

int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    return evp_cipher_asn1_to_param_ex(c, type, NULL);
}

int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *ctx, ASN1_TYPE *type)
{
    int i = 0;
    unsigned int l;

    if (type != NULL) {
        unsigned char iv[EVP_MAX_IV_LENGTH];

        l = EVP_CIPHER_CTX_get_iv_length(ctx);
        if (!ossl_assert(l <= sizeof(iv)))
            return -1;
        i = ASN1_TYPE_get_octetstring(type, iv, l);
        if (i != (int)l)
            return -1;

        if (!EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv, -1))
            return -1;
    }
    return i;
}

int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    int i = 0;
    unsigned int j;
    unsigned char *oiv = NULL;

    if (type != NULL) {
        oiv = (unsigned char *)EVP_CIPHER_CTX_original_iv(c);
        j = EVP_CIPHER_CTX_get_iv_length(c);
        OPENSSL_assert(j <= sizeof(c->iv));
        i = ASN1_TYPE_set_octetstring(type, oiv, j);
    }
    return i;
}

int evp_cipher_param_to_asn1_ex(EVP_CIPHER_CTX *c, ASN1_TYPE *type,
                                evp_cipher_aead_asn1_params *asn1_params)
{
    int ret = -1;                /* Assume the worst */
    const EVP_CIPHER *cipher = c->cipher;

    /*
     * For legacy implementations, we detect custom AlgorithmIdentifier
     * parameter handling by checking if the function pointer
     * cipher->set_asn1_parameters is set.  We know that this pointer
     * is NULL for provided implementations.
     *
     * Otherwise, for any implementation, we check the flag
     * EVP_CIPH_FLAG_CUSTOM_ASN1.  If it isn't set, we apply
     * default AI parameter extraction.
     *
     * Otherwise, for provided implementations, we convert |type| to
     * a DER encoded blob and pass to the implementation in OSSL_PARAM
     * form.
     *
     * If none of the above applies, this operation is unsupported.
     */
    if (cipher->set_asn1_parameters != NULL) {
        ret = cipher->set_asn1_parameters(c, type);
    } else if ((EVP_CIPHER_get_flags(cipher) & EVP_CIPH_FLAG_CUSTOM_ASN1) == 0) {
        switch (EVP_CIPHER_get_mode(cipher)) {
        case EVP_CIPH_WRAP_MODE:
            if (EVP_CIPHER_is_a(cipher, SN_id_smime_alg_CMS3DESwrap))
                ASN1_TYPE_set(type, V_ASN1_NULL, NULL);
            ret = 1;
            break;

        case EVP_CIPH_GCM_MODE:
            ret = evp_cipher_set_asn1_aead_params(c, type, asn1_params);
            break;

        case EVP_CIPH_CCM_MODE:
        case EVP_CIPH_XTS_MODE:
        case EVP_CIPH_OCB_MODE:
            ret = -2;
            break;

        default:
            ret = EVP_CIPHER_set_asn1_iv(c, type);
        }
    } else if (cipher->prov != NULL) {
        OSSL_PARAM params[3], *p = params;
        unsigned char *der = NULL, *derp;

        /*
         * We make two passes, the first to get the appropriate buffer size,
         * and the second to get the actual value.
         */
        *p++ = OSSL_PARAM_construct_octet_string(
                       OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS,
                       NULL, 0);
        *p = OSSL_PARAM_construct_end();

        if (!EVP_CIPHER_CTX_get_params(c, params))
            goto err;

        /* ... but, we should get a return size too! */
        if (OSSL_PARAM_modified(params)
            && params[0].return_size != 0
            && (der = OPENSSL_malloc(params[0].return_size)) != NULL) {
            params[0].data = der;
            params[0].data_size = params[0].return_size;
            OSSL_PARAM_set_all_unmodified(params);
            derp = der;
            if (EVP_CIPHER_CTX_get_params(c, params)
                && OSSL_PARAM_modified(params)
                && d2i_ASN1_TYPE(&type, (const unsigned char **)&derp,
                                 params[0].return_size) != NULL) {
                ret = 1;
            }
            OPENSSL_free(der);
        }
    } else {
        ret = -2;
    }

 err:
    if (ret == -2)
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_CIPHER);
    else if (ret <= 0)
        ERR_raise(ERR_LIB_EVP, EVP_R_CIPHER_PARAMETER_ERROR);
    if (ret < -1)
        ret = -1;
    return ret;
}

int evp_cipher_asn1_to_param_ex(EVP_CIPHER_CTX *c, ASN1_TYPE *type,
                                evp_cipher_aead_asn1_params *asn1_params)
{
    int ret = -1;                /* Assume the worst */
    const EVP_CIPHER *cipher = c->cipher;

    /*
     * For legacy implementations, we detect custom AlgorithmIdentifier
     * parameter handling by checking if there the function pointer
     * cipher->get_asn1_parameters is set.  We know that this pointer
     * is NULL for provided implementations.
     *
     * Otherwise, for any implementation, we check the flag
     * EVP_CIPH_FLAG_CUSTOM_ASN1.  If it isn't set, we apply
     * default AI parameter creation.
     *
     * Otherwise, for provided implementations, we get the AI parameter
     * in DER encoded form from the implementation by requesting the
     * appropriate OSSL_PARAM and converting the result to a ASN1_TYPE.
     *
     * If none of the above applies, this operation is unsupported.
     */
    if (cipher->get_asn1_parameters != NULL) {
        ret = cipher->get_asn1_parameters(c, type);
    } else if ((EVP_CIPHER_get_flags(cipher) & EVP_CIPH_FLAG_CUSTOM_ASN1) == 0) {
        switch (EVP_CIPHER_get_mode(cipher)) {
        case EVP_CIPH_WRAP_MODE:
            ret = 1;
            break;

        case EVP_CIPH_GCM_MODE:
            ret = evp_cipher_get_asn1_aead_params(c, type, asn1_params);
            break;

        case EVP_CIPH_CCM_MODE:
        case EVP_CIPH_XTS_MODE:
        case EVP_CIPH_OCB_MODE:
            ret = -2;
            break;

        default:
            ret = EVP_CIPHER_get_asn1_iv(c, type) >= 0 ? 1 : -1;
        }
    } else if (cipher->prov != NULL) {
        OSSL_PARAM params[3], *p = params;
        unsigned char *der = NULL;
        int derl = -1;

        if ((derl = i2d_ASN1_TYPE(type, &der)) >= 0) {
            *p++ =
                OSSL_PARAM_construct_octet_string(
                        OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS,
                        der, (size_t)derl);
            *p = OSSL_PARAM_construct_end();
            if (EVP_CIPHER_CTX_set_params(c, params))
                ret = 1;
            OPENSSL_free(der);
        }
    } else {
        ret = -2;
    }

    if (ret == -2)
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_CIPHER);
    else if (ret <= 0)
        ERR_raise(ERR_LIB_EVP, EVP_R_CIPHER_PARAMETER_ERROR);
    if (ret < -1)
        ret = -1;
    return ret;
}

int evp_cipher_get_asn1_aead_params(EVP_CIPHER_CTX *c, ASN1_TYPE *type,
                                    evp_cipher_aead_asn1_params *asn1_params)
{
    int i = 0;
    long tl;
    unsigned char iv[EVP_MAX_IV_LENGTH];

    if (type == NULL || asn1_params == NULL)
        return 0;

    i = ossl_asn1_type_get_octetstring_int(type, &tl, NULL, EVP_MAX_IV_LENGTH);
    if (i <= 0)
        return -1;
    ossl_asn1_type_get_octetstring_int(type, &tl, iv, i);

    memcpy(asn1_params->iv, iv, i);
    asn1_params->iv_len = i;

    return i;
}

int evp_cipher_set_asn1_aead_params(EVP_CIPHER_CTX *c, ASN1_TYPE *type,
                                    evp_cipher_aead_asn1_params *asn1_params)
{
    if (type == NULL || asn1_params == NULL)
        return 0;

    return ossl_asn1_type_set_octetstring_int(type, asn1_params->tag_len,
                                              asn1_params->iv,
                                              asn1_params->iv_len);
}
#endif /* !defined(FIPS_MODULE) */

/* Convert the various cipher NIDs and dummies to a proper OID NID */
int EVP_CIPHER_get_type(const EVP_CIPHER *cipher)
{
    int nid;
    nid = EVP_CIPHER_get_nid(cipher);

    switch (nid) {

    case NID_rc2_cbc:
    case NID_rc2_64_cbc:
    case NID_rc2_40_cbc:

        return NID_rc2_cbc;

    case NID_rc4:
    case NID_rc4_40:

        return NID_rc4;

    case NID_aes_128_cfb128:
    case NID_aes_128_cfb8:
    case NID_aes_128_cfb1:

        return NID_aes_128_cfb128;

    case NID_aes_192_cfb128:
    case NID_aes_192_cfb8:
    case NID_aes_192_cfb1:

        return NID_aes_192_cfb128;

    case NID_aes_256_cfb128:
    case NID_aes_256_cfb8:
    case NID_aes_256_cfb1:

        return NID_aes_256_cfb128;

    case NID_des_cfb64:
    case NID_des_cfb8:
    case NID_des_cfb1:

        return NID_des_cfb64;

    case NID_des_ede3_cfb64:
    case NID_des_ede3_cfb8:
    case NID_des_ede3_cfb1:

        return NID_des_cfb64;

    default:
#ifdef FIPS_MODULE
        return NID_undef;
#else
        {
            /* Check it has an OID and it is valid */
            ASN1_OBJECT *otmp = OBJ_nid2obj(nid);

            if (OBJ_get0_data(otmp) == NULL)
                nid = NID_undef;
            ASN1_OBJECT_free(otmp);
            return nid;
        }
#endif
    }
}

int evp_cipher_cache_constants(EVP_CIPHER *cipher)
{
    int ok, aead = 0, custom_iv = 0, cts = 0, multiblock = 0, randkey = 0;
    size_t ivlen = 0;
    size_t blksz = 0;
    size_t keylen = 0;
    unsigned int mode = 0;
    OSSL_PARAM params[10];

    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, &blksz);
    params[1] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &ivlen);
    params[2] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &keylen);
    params[3] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_MODE, &mode);
    params[4] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_AEAD, &aead);
    params[5] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_CUSTOM_IV,
                                         &custom_iv);
    params[6] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_CTS, &cts);
    params[7] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK,
                                         &multiblock);
    params[8] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY,
                                         &randkey);
    params[9] = OSSL_PARAM_construct_end();
    ok = evp_do_ciph_getparams(cipher, params) > 0;
    if (ok) {
        cipher->block_size = blksz;
        cipher->iv_len = ivlen;
        cipher->key_len = keylen;
        cipher->flags = mode;
        if (aead)
            cipher->flags |= EVP_CIPH_FLAG_AEAD_CIPHER;
        if (custom_iv)
            cipher->flags |= EVP_CIPH_CUSTOM_IV;
        if (cts)
            cipher->flags |= EVP_CIPH_FLAG_CTS;
        if (multiblock)
            cipher->flags |= EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK;
        if (cipher->ccipher != NULL)
            cipher->flags |= EVP_CIPH_FLAG_CUSTOM_CIPHER;
        if (randkey)
            cipher->flags |= EVP_CIPH_RAND_KEY;
        if (OSSL_PARAM_locate_const(EVP_CIPHER_gettable_ctx_params(cipher),
                                    OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS))
            cipher->flags |= EVP_CIPH_FLAG_CUSTOM_ASN1;
    }
    return ok;
}

int EVP_CIPHER_get_block_size(const EVP_CIPHER *cipher)
{
    return cipher->block_size;
}

int EVP_CIPHER_CTX_get_block_size(const EVP_CIPHER_CTX *ctx)
{
    return EVP_CIPHER_get_block_size(ctx->cipher);
}

int EVP_CIPHER_impl_ctx_size(const EVP_CIPHER *e)
{
    return e->ctx_size;
}

int EVP_Cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
               const unsigned char *in, unsigned int inl)
{
    if (ctx->cipher->prov != NULL) {
        /*
         * If the provided implementation has a ccipher function, we use it,
         * and translate its return value like this: 0 => -1, 1 => outlen
         *
         * Otherwise, we call the cupdate function if in != NULL, or cfinal
         * if in == NULL.  Regardless of which, we return what we got.
         */
        int ret = -1;
        size_t outl = 0;
        size_t blocksize = EVP_CIPHER_CTX_get_block_size(ctx);

        if (ctx->cipher->ccipher != NULL)
            ret =  ctx->cipher->ccipher(ctx->algctx, out, &outl,
                                        inl + (blocksize == 1 ? 0 : blocksize),
                                        in, (size_t)inl)
                ? (int)outl : -1;
        else if (in != NULL)
            ret = ctx->cipher->cupdate(ctx->algctx, out, &outl,
                                       inl + (blocksize == 1 ? 0 : blocksize),
                                       in, (size_t)inl);
        else
            ret = ctx->cipher->cfinal(ctx->algctx, out, &outl,
                                      blocksize == 1 ? 0 : blocksize);

        return ret;
    }

    return ctx->cipher->do_cipher(ctx, out, in, inl);
}

#ifndef OPENSSL_NO_DEPRECATED_3_0
const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->cipher;
}
#endif

const EVP_CIPHER *EVP_CIPHER_CTX_get0_cipher(const EVP_CIPHER_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->cipher;
}

EVP_CIPHER *EVP_CIPHER_CTX_get1_cipher(EVP_CIPHER_CTX *ctx)
{
    EVP_CIPHER *cipher;

    if (ctx == NULL)
        return NULL;
    cipher = (EVP_CIPHER *)ctx->cipher;
    if (!EVP_CIPHER_up_ref(cipher))
        return NULL;
    return cipher;
}

int EVP_CIPHER_CTX_is_encrypting(const EVP_CIPHER_CTX *ctx)
{
    return ctx->encrypt;
}

unsigned long EVP_CIPHER_get_flags(const EVP_CIPHER *cipher)
{
    return cipher->flags;
}

void *EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX *ctx)
{
    return ctx->app_data;
}

void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data)
{
    ctx->app_data = data;
}

void *EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher_data;
}

void *EVP_CIPHER_CTX_set_cipher_data(EVP_CIPHER_CTX *ctx, void *cipher_data)
{
    void *old_cipher_data;

    old_cipher_data = ctx->cipher_data;
    ctx->cipher_data = cipher_data;

    return old_cipher_data;
}

int EVP_CIPHER_get_iv_length(const EVP_CIPHER *cipher)
{
    return cipher->iv_len;
}

int EVP_CIPHER_CTX_get_iv_length(const EVP_CIPHER_CTX *ctx)
{
    if (ctx->iv_len < 0) {
        int rv, len = EVP_CIPHER_get_iv_length(ctx->cipher);
        size_t v = len;
        OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

        if (ctx->cipher->get_ctx_params != NULL) {
            params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN,
                                                    &v);
            rv = evp_do_ciph_ctx_getparams(ctx->cipher, ctx->algctx, params);
            if (rv > 0) {
                if (OSSL_PARAM_modified(params)
                        && !OSSL_PARAM_get_int(params, &len))
                    return -1;
            } else if (rv != EVP_CTRL_RET_UNSUPPORTED) {
                return -1;
            }
        }
        /* Code below to be removed when legacy support is dropped. */
        else if ((EVP_CIPHER_get_flags(ctx->cipher)
                  & EVP_CIPH_CUSTOM_IV_LENGTH) != 0) {
            rv = EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX *)ctx, EVP_CTRL_GET_IVLEN,
                                     0, &len);
            if (rv <= 0)
                return -1;
        }
        /*-
         * Casting away the const is annoying but required here.  We need to
         * cache the result for performance reasons.
         */
        ((EVP_CIPHER_CTX *)ctx)->iv_len = len;
    }
    return ctx->iv_len;
}

int EVP_CIPHER_CTX_get_tag_length(const EVP_CIPHER_CTX *ctx)
{
    int ret;
    size_t v = 0;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &v);
    ret = evp_do_ciph_ctx_getparams(ctx->cipher, ctx->algctx, params);
    return ret == 1 ? (int)v : 0;
}

#ifndef OPENSSL_NO_DEPRECATED_3_0
const unsigned char *EVP_CIPHER_CTX_original_iv(const EVP_CIPHER_CTX *ctx)
{
    int ok;
    const unsigned char *v = ctx->oiv;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

    params[0] =
        OSSL_PARAM_construct_octet_ptr(OSSL_CIPHER_PARAM_IV,
                                       (void **)&v, sizeof(ctx->oiv));
    ok = evp_do_ciph_ctx_getparams(ctx->cipher, ctx->algctx, params);

    return ok != 0 ? v : NULL;
}

/*
 * OSSL_PARAM_OCTET_PTR gets us the pointer to the running IV in the provider
 */
const unsigned char *EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx)
{
    int ok;
    const unsigned char *v = ctx->iv;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

    params[0] =
        OSSL_PARAM_construct_octet_ptr(OSSL_CIPHER_PARAM_UPDATED_IV,
                                       (void **)&v, sizeof(ctx->iv));
    ok = evp_do_ciph_ctx_getparams(ctx->cipher, ctx->algctx, params);

    return ok != 0 ? v : NULL;
}

unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx)
{
    int ok;
    unsigned char *v = ctx->iv;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

    params[0] =
        OSSL_PARAM_construct_octet_ptr(OSSL_CIPHER_PARAM_UPDATED_IV,
                                       (void **)&v, sizeof(ctx->iv));
    ok = evp_do_ciph_ctx_getparams(ctx->cipher, ctx->algctx, params);

    return ok != 0 ? v : NULL;
}
#endif /* OPENSSL_NO_DEPRECATED_3_0_0 */

int EVP_CIPHER_CTX_get_updated_iv(EVP_CIPHER_CTX *ctx, void *buf, size_t len)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

    params[0] =
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, buf, len);
    return evp_do_ciph_ctx_getparams(ctx->cipher, ctx->algctx, params) > 0;
}

int EVP_CIPHER_CTX_get_original_iv(EVP_CIPHER_CTX *ctx, void *buf, size_t len)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

    params[0] =
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_IV, buf, len);
    return evp_do_ciph_ctx_getparams(ctx->cipher, ctx->algctx, params) > 0;
}

unsigned char *EVP_CIPHER_CTX_buf_noconst(EVP_CIPHER_CTX *ctx)
{
    return ctx->buf;
}

int EVP_CIPHER_CTX_get_num(const EVP_CIPHER_CTX *ctx)
{
    int ok;
    unsigned int v = (unsigned int)ctx->num;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

    params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_NUM, &v);
    ok = evp_do_ciph_ctx_getparams(ctx->cipher, ctx->algctx, params);

    return ok != 0 ? (int)v : EVP_CTRL_RET_UNSUPPORTED;
}

int EVP_CIPHER_CTX_set_num(EVP_CIPHER_CTX *ctx, int num)
{
    int ok;
    unsigned int n = (unsigned int)num;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

    params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_NUM, &n);
    ok = evp_do_ciph_ctx_setparams(ctx->cipher, ctx->algctx, params);

    if (ok != 0)
        ctx->num = (int)n;
    return ok != 0;
}

int EVP_CIPHER_get_key_length(const EVP_CIPHER *cipher)
{
    return cipher->key_len;
}

int EVP_CIPHER_CTX_get_key_length(const EVP_CIPHER_CTX *ctx)
{
    if (ctx->key_len <= 0 && ctx->cipher->prov != NULL) {
        int ok;
        OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
        size_t len;

        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &len);
        ok = evp_do_ciph_ctx_getparams(ctx->cipher, ctx->algctx, params);
        if (ok <= 0)
            return EVP_CTRL_RET_UNSUPPORTED;

        /*-
         * The if branch should never be taken since EVP_MAX_KEY_LENGTH is
         * less than INT_MAX but best to be safe.
         *
         * Casting away the const is annoying but required here.  We need to
         * cache the result for performance reasons.
         */
        if (!OSSL_PARAM_get_int(params, &((EVP_CIPHER_CTX *)ctx)->key_len))
            return -1;
        ((EVP_CIPHER_CTX *)ctx)->key_len = (int)len;
    }
    return ctx->key_len;
}

int EVP_CIPHER_get_nid(const EVP_CIPHER *cipher)
{
    return cipher->nid;
}

int EVP_CIPHER_CTX_get_nid(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher->nid;
}

int EVP_CIPHER_is_a(const EVP_CIPHER *cipher, const char *name)
{
    if (cipher == NULL)
        return 0;
    if (cipher->prov != NULL)
        return evp_is_a(cipher->prov, cipher->name_id, NULL, name);
    return evp_is_a(NULL, 0, EVP_CIPHER_get0_name(cipher), name);
}

int evp_cipher_get_number(const EVP_CIPHER *cipher)
{
    return cipher->name_id;
}

const char *EVP_CIPHER_get0_name(const EVP_CIPHER *cipher)
{
    if (cipher->type_name != NULL)
        return cipher->type_name;
#ifndef FIPS_MODULE
    return OBJ_nid2sn(EVP_CIPHER_get_nid(cipher));
#else
    return NULL;
#endif
}

const char *EVP_CIPHER_get0_description(const EVP_CIPHER *cipher)
{
    if (cipher->description != NULL)
        return cipher->description;
#ifndef FIPS_MODULE
    return OBJ_nid2ln(EVP_CIPHER_get_nid(cipher));
#else
    return NULL;
#endif
}

int EVP_CIPHER_names_do_all(const EVP_CIPHER *cipher,
                            void (*fn)(const char *name, void *data),
                            void *data)
{
    if (cipher->prov != NULL)
        return evp_names_do_all(cipher->prov, cipher->name_id, fn, data);

    return 1;
}

const OSSL_PROVIDER *EVP_CIPHER_get0_provider(const EVP_CIPHER *cipher)
{
    return cipher->prov;
}

int EVP_CIPHER_get_mode(const EVP_CIPHER *cipher)
{
    return EVP_CIPHER_get_flags(cipher) & EVP_CIPH_MODE;
}

int EVP_MD_is_a(const EVP_MD *md, const char *name)
{
    if (md == NULL)
        return 0;
    if (md->prov != NULL)
        return evp_is_a(md->prov, md->name_id, NULL, name);
    return evp_is_a(NULL, 0, EVP_MD_get0_name(md), name);
}

int evp_md_get_number(const EVP_MD *md)
{
    return md->name_id;
}

const char *EVP_MD_get0_description(const EVP_MD *md)
{
    if (md->description != NULL)
        return md->description;
#ifndef FIPS_MODULE
    return OBJ_nid2ln(EVP_MD_nid(md));
#else
    return NULL;
#endif
}

const char *EVP_MD_get0_name(const EVP_MD *md)
{
    if (md == NULL)
        return NULL;
    if (md->type_name != NULL)
        return md->type_name;
#ifndef FIPS_MODULE
    return OBJ_nid2sn(EVP_MD_nid(md));
#else
    return NULL;
#endif
}

int EVP_MD_names_do_all(const EVP_MD *md,
                        void (*fn)(const char *name, void *data),
                        void *data)
{
    if (md->prov != NULL)
        return evp_names_do_all(md->prov, md->name_id, fn, data);

    return 1;
}

const OSSL_PROVIDER *EVP_MD_get0_provider(const EVP_MD *md)
{
    return md->prov;
}

int EVP_MD_get_type(const EVP_MD *md)
{
    return md->type;
}

int EVP_MD_get_pkey_type(const EVP_MD *md)
{
    return md->pkey_type;
}

int EVP_MD_get_block_size(const EVP_MD *md)
{
    if (md == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_MESSAGE_DIGEST_IS_NULL);
        return -1;
    }
    return md->block_size;
}

int EVP_MD_get_size(const EVP_MD *md)
{
    if (md == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_MESSAGE_DIGEST_IS_NULL);
        return -1;
    }
    return md->md_size;
}

unsigned long EVP_MD_get_flags(const EVP_MD *md)
{
    return md->flags;
}

EVP_MD *EVP_MD_meth_new(int md_type, int pkey_type)
{
    EVP_MD *md = evp_md_new();

    if (md != NULL) {
        md->type = md_type;
        md->pkey_type = pkey_type;
        md->origin = EVP_ORIG_METH;
    }
    return md;
}

EVP_MD *EVP_MD_meth_dup(const EVP_MD *md)
{
    EVP_MD *to = NULL;

    /*
     * Non-legacy EVP_MDs can't be duplicated like this.
     * Use EVP_MD_up_ref() instead.
     */
    if (md->prov != NULL)
        return NULL;

    if ((to = EVP_MD_meth_new(md->type, md->pkey_type)) != NULL) {
        CRYPTO_REF_COUNT refcnt = to->refcnt;

        memcpy(to, md, sizeof(*to));
        to->refcnt = refcnt;
        to->origin = EVP_ORIG_METH;
    }
    return to;
}

void evp_md_free_int(EVP_MD *md)
{
    OPENSSL_free(md->type_name);
    ossl_provider_free(md->prov);
    CRYPTO_FREE_REF(&md->refcnt);
    OPENSSL_free(md);
}

void EVP_MD_meth_free(EVP_MD *md)
{
    if (md == NULL || md->origin != EVP_ORIG_METH)
       return;

    evp_md_free_int(md);
}

int EVP_MD_meth_set_input_blocksize(EVP_MD *md, int blocksize)
{
    if (md->block_size != 0)
        return 0;

    md->block_size = blocksize;
    return 1;
}
int EVP_MD_meth_set_result_size(EVP_MD *md, int resultsize)
{
    if (md->md_size != 0)
        return 0;

    md->md_size = resultsize;
    return 1;
}
int EVP_MD_meth_set_app_datasize(EVP_MD *md, int datasize)
{
    if (md->ctx_size != 0)
        return 0;

    md->ctx_size = datasize;
    return 1;
}
int EVP_MD_meth_set_flags(EVP_MD *md, unsigned long flags)
{
    if (md->flags != 0)
        return 0;

    md->flags = flags;
    return 1;
}
int EVP_MD_meth_set_init(EVP_MD *md, int (*init)(EVP_MD_CTX *ctx))
{
    if (md->init != NULL)
        return 0;

    md->init = init;
    return 1;
}
int EVP_MD_meth_set_update(EVP_MD *md, int (*update)(EVP_MD_CTX *ctx,
                                                     const void *data,
                                                     size_t count))
{
    if (md->update != NULL)
        return 0;

    md->update = update;
    return 1;
}
int EVP_MD_meth_set_final(EVP_MD *md, int (*final)(EVP_MD_CTX *ctx,
                                                   unsigned char *md))
{
    if (md->final != NULL)
        return 0;

    md->final = final;
    return 1;
}
int EVP_MD_meth_set_copy(EVP_MD *md, int (*copy)(EVP_MD_CTX *to,
                                                 const EVP_MD_CTX *from))
{
    if (md->copy != NULL)
        return 0;

    md->copy = copy;
    return 1;
}
int EVP_MD_meth_set_cleanup(EVP_MD *md, int (*cleanup)(EVP_MD_CTX *ctx))
{
    if (md->cleanup != NULL)
        return 0;

    md->cleanup = cleanup;
    return 1;
}
int EVP_MD_meth_set_ctrl(EVP_MD *md, int (*ctrl)(EVP_MD_CTX *ctx, int cmd,
                                                 int p1, void *p2))
{
    if (md->md_ctrl != NULL)
        return 0;

    md->md_ctrl = ctrl;
    return 1;
}

int EVP_MD_meth_get_input_blocksize(const EVP_MD *md)
{
    return md->block_size;
}
int EVP_MD_meth_get_result_size(const EVP_MD *md)
{
    return md->md_size;
}
int EVP_MD_meth_get_app_datasize(const EVP_MD *md)
{
    return md->ctx_size;
}
unsigned long EVP_MD_meth_get_flags(const EVP_MD *md)
{
    return md->flags;
}
int (*EVP_MD_meth_get_init(const EVP_MD *md))(EVP_MD_CTX *ctx)
{
    return md->init;
}
int (*EVP_MD_meth_get_update(const EVP_MD *md))(EVP_MD_CTX *ctx,
                                                const void *data,
                                                size_t count)
{
    return md->update;
}
int (*EVP_MD_meth_get_final(const EVP_MD *md))(EVP_MD_CTX *ctx,
                                               unsigned char *md)
{
    return md->final;
}
int (*EVP_MD_meth_get_copy(const EVP_MD *md))(EVP_MD_CTX *to,
                                              const EVP_MD_CTX *from)
{
    return md->copy;
}
int (*EVP_MD_meth_get_cleanup(const EVP_MD *md))(EVP_MD_CTX *ctx)
{
    return md->cleanup;
}
int (*EVP_MD_meth_get_ctrl(const EVP_MD *md))(EVP_MD_CTX *ctx, int cmd,
                                              int p1, void *p2)
{
    return md->md_ctrl;
}

#ifndef OPENSSL_NO_DEPRECATED_3_0
const EVP_MD *EVP_MD_CTX_md(const EVP_MD_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->reqdigest;
}
#endif

const EVP_MD *EVP_MD_CTX_get0_md(const EVP_MD_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->reqdigest;
}

EVP_MD *EVP_MD_CTX_get1_md(EVP_MD_CTX *ctx)
{
    EVP_MD *md;

    if (ctx == NULL)
        return NULL;
    md = (EVP_MD *)ctx->reqdigest;
    if (md == NULL || !EVP_MD_up_ref(md))
        return NULL;
    return md;
}

EVP_PKEY_CTX *EVP_MD_CTX_get_pkey_ctx(const EVP_MD_CTX *ctx)
{
    return ctx->pctx;
}

#if !defined(FIPS_MODULE)
void EVP_MD_CTX_set_pkey_ctx(EVP_MD_CTX *ctx, EVP_PKEY_CTX *pctx)
{
    /*
     * it's reasonable to set NULL pctx (a.k.a clear the ctx->pctx), so
     * we have to deal with the cleanup job here.
     */
    if (!EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX))
        EVP_PKEY_CTX_free(ctx->pctx);

    ctx->pctx = pctx;

    if (pctx != NULL) {
        /* make sure pctx is not freed when destroying EVP_MD_CTX */
        EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX);
    } else {
        EVP_MD_CTX_clear_flags(ctx, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX);
    }
}
#endif /* !defined(FIPS_MODULE) */

void *EVP_MD_CTX_get0_md_data(const EVP_MD_CTX *ctx)
{
    return ctx->md_data;
}

int (*EVP_MD_CTX_update_fn(EVP_MD_CTX *ctx))(EVP_MD_CTX *ctx,
                                             const void *data, size_t count)
{
    return ctx->update;
}

void EVP_MD_CTX_set_update_fn(EVP_MD_CTX *ctx,
                              int (*update) (EVP_MD_CTX *ctx,
                                             const void *data, size_t count))
{
    ctx->update = update;
}

void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags)
{
    ctx->flags |= flags;
}

void EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx, int flags)
{
    ctx->flags &= ~flags;
}

int EVP_MD_CTX_test_flags(const EVP_MD_CTX *ctx, int flags)
{
    return (ctx->flags & flags);
}

static int evp_cipher_ctx_enable_use_bits(EVP_CIPHER_CTX *ctx,
                                          unsigned int enable)
{
    OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END };

    params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_USE_BITS, &enable);
    return EVP_CIPHER_CTX_set_params(ctx, params);
}

void EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags)
{
    int oldflags = ctx->flags;

    ctx->flags |= flags;
    if (((oldflags ^ ctx->flags) & EVP_CIPH_FLAG_LENGTH_BITS) != 0)
        evp_cipher_ctx_enable_use_bits(ctx, 1);
}

void EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX *ctx, int flags)
{
    int oldflags = ctx->flags;

    ctx->flags &= ~flags;
    if (((oldflags ^ ctx->flags) & EVP_CIPH_FLAG_LENGTH_BITS) != 0)
        evp_cipher_ctx_enable_use_bits(ctx, 0);
}

int EVP_CIPHER_CTX_test_flags(const EVP_CIPHER_CTX *ctx, int flags)
{
    return (ctx->flags & flags);
}

#if !defined(FIPS_MODULE)

int EVP_PKEY_CTX_set_group_name(EVP_PKEY_CTX *ctx, const char *name)
{
    OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END };

    if (ctx == NULL || !EVP_PKEY_CTX_IS_GEN_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    if (name == NULL)
        return -1;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)name, 0);
    return EVP_PKEY_CTX_set_params(ctx, params);
}

int EVP_PKEY_CTX_get_group_name(EVP_PKEY_CTX *ctx, char *name, size_t namelen)
{
    OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END };
    OSSL_PARAM *p = params;

    if (ctx == NULL || !EVP_PKEY_CTX_IS_GEN_OP(ctx)) {
        /* There is no legacy support for this */
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    if (name == NULL)
        return -1;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                            name, namelen);
    if (!EVP_PKEY_CTX_get_params(ctx, params))
        return -1;
    return 1;
}

/*
 * evp_pkey_keygen() abstracts from the explicit use of B<EVP_PKEY_CTX>
 * while providing a generic way of generating a new asymmetric key pair
 * of algorithm type I<name> (e.g., C<RSA> or C<EC>).
 * The library context I<libctx> and property query I<propq>
 * are used when fetching algorithms from providers.
 * The I<params> specify algorithm-specific parameters
 * such as the RSA modulus size or the name of an EC curve.
 */
static EVP_PKEY *evp_pkey_keygen(OSSL_LIB_CTX *libctx, const char *name,
                                 const char *propq, const OSSL_PARAM *params)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, name, propq);

    if (ctx != NULL
            && EVP_PKEY_keygen_init(ctx) > 0
            && EVP_PKEY_CTX_set_params(ctx, params))
        (void)EVP_PKEY_generate(ctx, &pkey);

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

EVP_PKEY *EVP_PKEY_Q_keygen(OSSL_LIB_CTX *libctx, const char *propq,
                            const char *type, ...)
{
    va_list args;
    size_t bits;
    char *name;
    OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END };
    EVP_PKEY *ret = NULL;

    va_start(args, type);

    if (OPENSSL_strcasecmp(type, "RSA") == 0) {
        bits = va_arg(args, size_t);
        params[0] = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_RSA_BITS, &bits);
    } else if (OPENSSL_strcasecmp(type, "EC") == 0) {
        name = va_arg(args, char *);
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                     name, 0);
    } else if (OPENSSL_strcasecmp(type, "ED25519") != 0
               && OPENSSL_strcasecmp(type, "X25519") != 0
               && OPENSSL_strcasecmp(type, "ED448") != 0
               && OPENSSL_strcasecmp(type, "X448") != 0
               && OPENSSL_strcasecmp(type, "SM2") != 0) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_INVALID_ARGUMENT);
        goto end;
    }
    ret = evp_pkey_keygen(libctx, type, propq, params);

 end:
    va_end(args);
    return ret;
}

#endif /* !defined(FIPS_MODULE) */

typedef struct ossl_signature_md_algorithms_st {
    CRYPTO_RWLOCK *lock;
    char *signing;
    char *verification;
} OSSL_SIGNATURE_MD_ALGORITHMS;

void ossl_ctx_signature_md_algorithms_free(void *vsmdalgs)
{
    OSSL_SIGNATURE_MD_ALGORITHMS *smdalgs = vsmdalgs;

    if (smdalgs != NULL) {
        CRYPTO_THREAD_lock_free(smdalgs->lock);
        OPENSSL_free(smdalgs->signing);
        OPENSSL_free(smdalgs->verification);
        OPENSSL_free(smdalgs);
    }
}

void *ossl_ctx_signature_md_algorithms_new(OSSL_LIB_CTX *ctx)
{
    OSSL_SIGNATURE_MD_ALGORITHMS *smdalgs = OPENSSL_zalloc(sizeof(OSSL_SIGNATURE_MD_ALGORITHMS));
    if (smdalgs == NULL)
        return NULL;

    smdalgs->lock = CRYPTO_THREAD_lock_new();
    if (smdalgs->lock == NULL)
        goto err;

    return smdalgs;

err:
    CRYPTO_THREAD_lock_free(smdalgs->lock);
    OPENSSL_free(smdalgs);
    return NULL;
}

#ifndef FIPS_MODULE

int EVP_signature_md_algorithms_set(OSSL_LIB_CTX *libctx, int usecase,
                                    const char *value)
{
    char *copy = NULL;
    OSSL_SIGNATURE_MD_ALGORITHMS *smdalgs = ossl_lib_ctx_get_data(
        libctx, OSSL_LIB_CTX_SIGNATURE_MD_ALGORITHMS_INDEX);
    if (smdalgs == NULL)
        return 0;

    copy = OPENSSL_strdup(value);
    if (copy == NULL)
        goto err;

    if (!CRYPTO_THREAD_write_lock(smdalgs->lock))
        goto err;

    switch (usecase) {
    case EVP_SIGNATURE_MD_ALGORITHMS_SIGNING:
        OPENSSL_free(smdalgs->signing);
        smdalgs->signing = copy;
        break;
    case EVP_SIGNATURE_MD_ALGORITHMS_VERIFICATION:
        OPENSSL_free(smdalgs->verification);
        smdalgs->verification = copy;
        break;
    default:
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_INVALID_ARGUMENT);
        goto unlock_err;
    }
    CRYPTO_THREAD_unlock(smdalgs->lock);

    return 1;

unlock_err:
    CRYPTO_THREAD_unlock(smdalgs->lock);

err:
    OPENSSL_free(copy);
    return 0;
}

int EVP_signature_md_algorithm_set(OSSL_LIB_CTX *libctx, int usecase,
                                   const EVP_MD *md, int allow)
{
    const char *digest_algorithms = NULL;
    const char *p;
    char *w;

    char **parts = NULL;
    size_t parts_capacity = 0;
    size_t parts_size = 0;

    char *new_digest_algorithms = NULL;
    size_t new_digest_algorithms_size = 0;

    char *buf = NULL;

    int already_present = 0;
    int allowlist = 1;
    size_t idx;

    OSSL_SIGNATURE_MD_ALGORITHMS *smdalgs = ossl_lib_ctx_get_data(
        libctx, OSSL_LIB_CTX_SIGNATURE_MD_ALGORITHMS_INDEX);
    if (smdalgs == NULL)
        return 0;

    if (!CRYPTO_THREAD_write_lock(smdalgs->lock))
        goto err;

    switch (usecase) {
    case EVP_SIGNATURE_MD_ALGORITHMS_SIGNING:
        digest_algorithms = smdalgs->signing;
        break;
    case EVP_SIGNATURE_MD_ALGORITHMS_VERIFICATION:
        digest_algorithms = smdalgs->verification;
        break;
    default:
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_INVALID_ARGUMENT);
        goto unlock_err;
    }

    if (digest_algorithms == NULL || *digest_algorithms == '\0' || strcmp("ALL", digest_algorithms) == 0) {
        /* If digest_algorithms is "ALL", NULL or empty, everything is allowed. */
        parts_capacity++;
        parts = OPENSSL_realloc(parts, parts_capacity * sizeof(*parts));
        if (parts == NULL)
            goto unlock_err;

        parts[0] = OPENSSL_strdup("ALL");
        if (parts[0] == NULL)
            goto unlock_err;
        parts_size++;

        allowlist = 0;
    } else {
        /* Otherwise, split into entries and assign them to parts for easier
         * processing. */

        char **new_parts = NULL;
        parts_capacity += 16;
        new_parts = OPENSSL_realloc(parts, parts_capacity * sizeof(*parts));
        if (new_parts == NULL)
            goto unlock_err;
        parts = new_parts;

        p = digest_algorithms;

        while (p && *p != '\0') {
            size_t len;
            char *end = strchr(p, ':');
            const char *next = NULL;

            if (end == NULL) {
                len = strlen(p);
                next = p + len;
            } else {
                len = end - p;
                next = end + 1;
            }

            /* Skip empty entries or entries that are too long to be valid
             * names. */
            if (len > 0 && len < OSSL_MAX_NAME_SIZE) {
                char candidate[OSSL_MAX_NAME_SIZE + 1];

                strncpy(candidate, p, len);
                candidate[len] = '\0';

                if (parts_size == 0 && strcmp(candidate, "ALL") == 0) {
                    /* If the first element is "ALL", all other entries should
                     * be deny entries. */
                    allowlist = 0;
                } else if ((allowlist && *candidate == '!') || (!allowlist && *candidate != '!')) {
                    /* If no entries are allowed by default, ignore explicit
                     * deny entries. If everything is allowed by default,
                     * ignore everything that doesn't explicitly deny an
                     * algorithm. */
                    p = next;
                    continue;
                }

                if (allowlist && EVP_MD_is_a(md, candidate)) {
                    if (!allow || already_present) {
                        /* This entry is on the allowed list, but the user does
                         * not want to allow it. It needs to be removed, so
                         * skip it.
                         *
                         * OR
                         * 
                         * There was a previous entry for this algorithm
                         * already, remove the duplicate by skipping it. */
                        p = next;
                        continue;
                    }

                    /* The entry that the user wanted to add is already
                     * present; remember this so we don't add it twice. */
                    already_present = 1;
                } else if (!allowlist && EVP_MD_is_a(md, candidate + 1)) {
                    if (allow || already_present) {
                        /* This entry denies the algorithm the user wants to
                         * allow. Skip it.
                         *
                         * OR
                         *
                         * There was a previous entry that denies this
                         * algorithm already, remove the duplicate by skipping
                         * it. */
                        p = next;
                        continue;
                    }

                    /* The algorithm the user wants to deny is already denied;
                     * remember this so that we don't add another deny
                     * statement. */
                    already_present = 1;
                }

                /* If we haven't hit a continue statement yet, the entry is
                 * either exactly what we want (and not a duplicate), or it
                 * doesn't match the algorithm specified in md, so just copy it
                 * unmodified. */
                if (parts_size >= parts_capacity) {
                    parts_capacity += 16;
                    new_parts = OPENSSL_realloc(parts, parts_capacity * sizeof(*parts));
                    if (new_parts != NULL)
                        goto unlock_err;
                    parts = new_parts;
                }

                parts[parts_size] = OPENSSL_strdup(candidate);
                if (parts[parts_size] == NULL)
                    goto unlock_err;
                parts_size++;
            }

            p = next;
        }
    }

    /* If an entry was not already present and the requested behavior does
     * not match the defualt, we have to add one. */
    if (!already_present && ((allowlist && allow) || (!allowlist && !allow))) {
        const char *digest_name = EVP_MD_get0_name(md);
        size_t digest_namelen = strlen(digest_name);

        buf = OPENSSL_zalloc(digest_namelen + 2);
        if (buf == NULL)
            goto unlock_err;

        BIO_snprintf(buf, digest_namelen + 2, "%s%s", allow ? "" : "!", digest_name);

        if (parts_size >= parts_capacity) {
            char **new_parts = NULL;
            parts_capacity++;
            new_parts = OPENSSL_realloc(parts, parts_capacity * sizeof(*parts));
            if (new_parts == NULL)
                goto unlock_err;
            parts = new_parts;
        }

        parts[parts_size] = OPENSSL_strdup(buf);
        if (parts[parts_size] == NULL)
            goto unlock_err;
        parts_size++;

        OPENSSL_free(buf);
        buf = NULL;
    }

    for (idx = 0; idx < parts_size; ++idx) {
        /* We need the length of the string plus one byte for either the
         * separating colon, or the trailing \0. */
        new_digest_algorithms_size += strlen(parts[idx]) + 1;
    }
    new_digest_algorithms = OPENSSL_zalloc(new_digest_algorithms_size);
    if (new_digest_algorithms == NULL)
        goto unlock_err;

    w = new_digest_algorithms;
    for (idx = 0; idx < parts_size; ++idx) {
        size_t len = strlen(parts[idx]);
        strcpy(w, parts[idx]);
        w += len;
        *w = (idx + 1 == parts_size) ? '\0' : ':';
        w++;
    }

    switch (usecase) {
    case EVP_SIGNATURE_MD_ALGORITHMS_SIGNING:
        OPENSSL_free(smdalgs->signing);
        smdalgs->signing = new_digest_algorithms;
        new_digest_algorithms = NULL;
        break;
    case EVP_SIGNATURE_MD_ALGORITHMS_VERIFICATION:
        OPENSSL_free(smdalgs->verification);
        smdalgs->verification = new_digest_algorithms;
        new_digest_algorithms = NULL;
        break;
    }

    CRYPTO_THREAD_unlock(smdalgs->lock);

    OPENSSL_free(new_digest_algorithms);
    for (idx = 0; idx < parts_size; ++idx) {
        OPENSSL_free(parts[idx]);
    }
    OPENSSL_free(parts);

    return 1;

unlock_err:
    CRYPTO_THREAD_unlock(smdalgs->lock);

err:
    OPENSSL_free(new_digest_algorithms);
    for (idx = 0; idx < parts_size; ++idx) {
        OPENSSL_free(parts[idx]);
    }
    OPENSSL_free(parts);
    OPENSSL_free(buf);
    return 0;
}

char *EVP_signature_md_algorithms_get(OSSL_LIB_CTX *libctx, int usecase)
{
    char *digests = NULL;
    OSSL_SIGNATURE_MD_ALGORITHMS *smdalgs = ossl_lib_ctx_get_data(
        libctx, OSSL_LIB_CTX_SIGNATURE_MD_ALGORITHMS_INDEX);
    if (smdalgs == NULL)
        goto err;

    if (!CRYPTO_THREAD_read_lock(smdalgs->lock))
        goto err;

    switch (usecase) {
    case EVP_SIGNATURE_MD_ALGORITHMS_SIGNING:
        digests = OPENSSL_strdup(smdalgs->signing);
        break;
    case EVP_SIGNATURE_MD_ALGORITHMS_VERIFICATION:
        digests = OPENSSL_strdup(smdalgs->verification);
        break;
    default:
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_INVALID_ARGUMENT);
        goto unlock_err;
    }

unlock_err:
    CRYPTO_THREAD_unlock(smdalgs->lock);

err:
    return digests;
}

int EVP_signature_md_algorithm_allowed(
        OSSL_LIB_CTX *libctx, int usecase, const EVP_MD *md, EVP_PKEY_CTX *ctx)
{
    const char *param_name;

    switch (usecase) {
        case EVP_SIGNATURE_MD_ALGORITHMS_SIGNING:
            param_name = OSSL_SIGNATURE_PARAM_DIGEST_ALGORITHMS_SIGNING;
            break;
        case EVP_SIGNATURE_MD_ALGORITHMS_VERIFICATION:
            param_name = OSSL_SIGNATURE_PARAM_DIGEST_ALGORITHMS_VERIFICATION;
            break;
        default:
            ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_INVALID_ARGUMENT);
            return -1;
    }

    if (ctx != NULL) {
        /* Check the given EVP_PKEY_CTX if the provider supports it. */
        OSSL_PARAM params_size[2];
        char *buf = NULL;
        OSSL_PARAM *p = NULL;
        const OSSL_PARAM *gettable_params = EVP_PKEY_CTX_gettable_params(ctx);

        params_size[0] = OSSL_PARAM_construct_utf8_string(param_name, NULL, 0);
        params_size[1] = OSSL_PARAM_construct_end();

        if (gettable_params == NULL || OSSL_PARAM_locate_const(gettable_params, param_name) == NULL)
            /* The provider either does not support checking, or no
             * restrictions are defined. Assume every digest is permitted. */
            return 1;

        if (!EVP_PKEY_CTX_get_params(ctx, params_size))
            return -1;
        if ((p = OSSL_PARAM_locate(params_size, param_name)) == NULL
                || p->return_size == 0
                || p->return_size == OSSL_PARAM_UNMODIFIED)
            /* The provider did not return a digest list, or it is empty;
             * assume everything is allowed. */
            return 1;

        buf = OPENSSL_zalloc(p->return_size + 1);
        if (buf == NULL)
            return -1;
        else {
            int result = 1;
            OSSL_PARAM params[2];

            params[0] = OSSL_PARAM_construct_utf8_string(param_name, buf, p->return_size + 1);
            params[1] = OSSL_PARAM_construct_end();

            if (!EVP_PKEY_CTX_get_params(ctx, params)) {
                OPENSSL_free(buf);
                return -1;
            }

            result = ossl_digest_in_allowlist(md, buf);
            OPENSSL_free(buf);
            return result;
        }
    } else {
        /* No EVP_PKEY_CTX available, check the given libctx */
        int result = 0;
        char *digest_algorithms = EVP_signature_md_algorithms_get(libctx, usecase);
        if (digest_algorithms == NULL)
            /* No restrictions configured, assume everything is allowed. */
            return 1;

        result = ossl_digest_in_allowlist(md, digest_algorithms);
        OPENSSL_free(digest_algorithms);
        return result;
    }
}

#endif /* !defined(FIPS_MODULE) */

int ossl_digest_in_allowlist(const EVP_MD *md, const char *digest_algorithms)
{
    const char *p = digest_algorithms;
    int allowlist = 1;
    int found = 0;

    if (digest_algorithms == NULL || *digest_algorithms == '\0') {
        /* If digest_algorithms is NULL or empty, allow everything. */
        allowlist = 0;
    } else if (strcmp("ALL", digest_algorithms) == 0) {
        /* Explicitly allowed all algorithms with no restrictions */
        return 1;
    } else if (strncmp("ALL:", digest_algorithms, 4) == 0) {
        /* If digest_algorithms starts with "ALL:" it is a denylist, otherwise
         * an allowlist. */
        allowlist = 0;
        p = p + 4;
    }

    while (p && *p != '\0') {
        size_t len;
        char *end = strchr(p, ':');
        const char *next = NULL;
        if (end == NULL) {
            len = strlen(p);
            next = p + len;
        } else {
            len = end - p;
            next = end + 1;
        }

        if ((*p != '!' && !allowlist) || (*p == '!' && allowlist) || len == 0) {
            /* Allowed algorithm, but the list started with "ALL:", so no need
             * to check, or denied algorithm, but none are implicitly allowed,
             * so skip the explicit deny. */
            p = next;
            continue;
        } else {
            char candidate[OSSL_MAX_NAME_SIZE];

            if (!allowlist) {
                /* skip the leading '!' */
                p++;
                len--;
            }

            if (len == 0 || len >= OSSL_MAX_NAME_SIZE - 1) {
                p = next;
                continue;
            }
            strncpy(candidate, p, len);
            candidate[len] = '\0';

            if (EVP_MD_is_a(md, candidate)) {
                found = 1;
                break;
            }
        }

        p = next;
    }

    if (allowlist != found)
        /* If the list is an allowlist, but the algorithm was not found, or the
         * list is a deny list and the algorithm was found, return false. */
        return 0;

    return 1;
}
