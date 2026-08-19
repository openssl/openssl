/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include "testutil.h"

/*
 * The padding value lives in the provider context while EVP keeps its own
 * EVP_CIPH_NO_PADDING flag, so the two can drift apart.  No built-in cipher
 * both reports the AEAD flag and honours padding, which leaves that
 * combination untested; the cipher below fills the gap.
 */

#define PAD_PROV_NAME "padding-test"
#define PAD_CIPHER_NAME "PADDED-AEAD"
/* Same cipher, except that it refuses to be told about padding at all. */
#define PAD_REJECT_CIPHER_NAME "PADDING-REJECT"
#define PAD_BLOCK_SIZE 16

typedef struct {
    unsigned int pad;
} PAD_CTX;

/* How many times the provider has been told what padding to use. */
static int pad_set_count = 0;

static OSSL_FUNC_cipher_newctx_fn pad_newctx;
static OSSL_FUNC_cipher_freectx_fn pad_freectx;
static OSSL_FUNC_cipher_dupctx_fn pad_dupctx;
static OSSL_FUNC_cipher_encrypt_init_fn pad_einit;
static OSSL_FUNC_cipher_decrypt_init_fn pad_dinit;
static OSSL_FUNC_cipher_update_fn pad_update;
static OSSL_FUNC_cipher_final_fn pad_final;
static OSSL_FUNC_cipher_get_params_fn pad_get_params;
static OSSL_FUNC_cipher_get_ctx_params_fn pad_get_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn pad_set_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn pad_gettable_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn pad_settable_ctx_params;

static void *pad_newctx(ossl_unused void *provctx)
{
    PAD_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        ctx->pad = 1;
    return ctx;
}

static void pad_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static void *pad_dupctx(void *vctx)
{
    PAD_CTX *ctx = OPENSSL_malloc(sizeof(*ctx));

    if (ctx != NULL)
        *ctx = *(PAD_CTX *)vctx;
    return ctx;
}

static int pad_init(void *vctx, const OSSL_PARAM params[])
{
    return pad_set_ctx_params(vctx, params);
}

static int pad_einit(void *vctx, ossl_unused const unsigned char *key,
    ossl_unused size_t keylen,
    ossl_unused const unsigned char *iv,
    ossl_unused size_t ivlen, const OSSL_PARAM params[])
{
    return pad_init(vctx, params);
}

static int pad_dinit(void *vctx, ossl_unused const unsigned char *key,
    ossl_unused size_t keylen,
    ossl_unused const unsigned char *iv,
    ossl_unused size_t ivlen, const OSSL_PARAM params[])
{
    return pad_init(vctx, params);
}

static int pad_update(ossl_unused void *vctx, unsigned char *out, size_t *outl,
    size_t outsize, const unsigned char *in, size_t inl)
{
    if (outsize < inl)
        return 0;
    memcpy(out, in, inl);
    *outl = inl;
    return 1;
}

static int pad_final(ossl_unused void *vctx, ossl_unused unsigned char *out,
    size_t *outl, ossl_unused size_t outsize)
{
    *outl = 0;
    return 1;
}

static int pad_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, PAD_BLOCK_SIZE))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, EVP_CIPH_CBC_MODE))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

static int pad_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PAD_CTX *ctx = vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->pad))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16))
        return 0;
    return 1;
}

static int pad_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PAD_CTX *ctx = vctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL) {
        if (!OSSL_PARAM_get_uint(p, &ctx->pad))
            return 0;
        pad_set_count++;
    }
    return 1;
}

static int pad_reject_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    if (params == NULL)
        return 1;
    if (OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING) != NULL)
        return 0;
    return 1;
}

static int pad_reject_einit(void *vctx, ossl_unused const unsigned char *key,
    ossl_unused size_t keylen,
    ossl_unused const unsigned char *iv,
    ossl_unused size_t ivlen, const OSSL_PARAM params[])
{
    return pad_reject_set_ctx_params(vctx, params);
}

static int pad_reject_dinit(void *vctx, ossl_unused const unsigned char *key,
    ossl_unused size_t keylen,
    ossl_unused const unsigned char *iv,
    ossl_unused size_t ivlen, const OSSL_PARAM params[])
{
    return pad_reject_set_ctx_params(vctx, params);
}

static const OSSL_PARAM pad_known_gettable_ctx_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *pad_gettable_ctx_params(ossl_unused void *cctx,
    ossl_unused void *provctx)
{
    return pad_known_gettable_ctx_params;
}

static const OSSL_PARAM pad_known_settable_ctx_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *pad_settable_ctx_params(ossl_unused void *cctx,
    ossl_unused void *provctx)
{
    return pad_known_settable_ctx_params;
}

static const OSSL_DISPATCH pad_cipher_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))pad_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))pad_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))pad_dupctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))pad_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))pad_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))pad_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))pad_final },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))pad_get_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))pad_get_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))pad_set_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
        (void (*)(void))pad_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
        (void (*)(void))pad_settable_ctx_params },
    OSSL_DISPATCH_END
};

static const OSSL_DISPATCH pad_reject_cipher_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))pad_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))pad_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))pad_reject_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))pad_reject_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))pad_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))pad_final },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))pad_get_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))pad_get_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
        (void (*)(void))pad_reject_set_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
        (void (*)(void))pad_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
        (void (*)(void))pad_settable_ctx_params },
    OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM pad_ciphers[] = {
    { PAD_CIPHER_NAME, "provider=" PAD_PROV_NAME, pad_cipher_functions },
    { PAD_REJECT_CIPHER_NAME, "provider=" PAD_PROV_NAME,
        pad_reject_cipher_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *pad_query(ossl_unused void *provctx,
    int operation_id, int *no_cache)
{
    *no_cache = 0;
    if (operation_id == OSSL_OP_CIPHER)
        return pad_ciphers;
    return NULL;
}

static const OSSL_DISPATCH pad_prov_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))pad_query },
    OSSL_DISPATCH_END
};

static int pad_prov_init(const OSSL_CORE_HANDLE *handle,
    ossl_unused const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out, void **provctx)
{
    *provctx = (void *)handle;
    *out = pad_prov_dispatch;
    return 1;
}

static OSSL_LIB_CTX *libctx = NULL;
static OSSL_PROVIDER *padprov = NULL;
/* The SKEY test needs a cipher with key management, which this provides. */
static OSSL_PROVIDER *defprov = NULL;

/* Reads the padding value held by the provider context. */
static int get_provider_padding(EVP_CIPHER_CTX *ctx, unsigned int *pad)
{
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, pad);
    params[1] = OSSL_PARAM_construct_end();
    return EVP_CIPHER_CTX_get_params(ctx, params);
}

/*
 * A no-padding request made through EVP_CIPHER_CTX_set_padding() has to
 * survive any later initialisation of the same context.
 */
static int test_set_padding_survives_reinit(void)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    static const unsigned char key[16] = { 0 };
    static const unsigned char iv[16] = { 0 };
    unsigned int pad;
    int ret = 0;

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(libctx, PAD_CIPHER_NAME,
                      "provider=" PAD_PROV_NAME))
        || !TEST_int_ne(EVP_CIPHER_get_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER,
            0)
        || !TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL))
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 1)
        || !TEST_true(EVP_CIPHER_CTX_set_padding(ctx, 0))
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 0))
        goto err;

    /* Re-initialising with the same cipher keeps the provider context. */
    if (!TEST_true(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL))
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 0))
        goto err;

    /* Re-initialising without a cipher does too. */
    if (!TEST_true(EVP_EncryptInit_ex2(ctx, NULL, key, iv, NULL))
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 0))
        goto err;

    /* Supplying the cipher again allocates a fresh provider context. */
    if (!TEST_true(EVP_CIPHER_CTX_reset(ctx))
        || !TEST_true(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL))
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 1))
        goto err;

    ret = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

/*
 * Padding set as a raw parameter has to behave the same way, which means EVP
 * must pick up the value rather than overwrite it on the next initialisation.
 */
static int test_padding_param_survives_reinit(void)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    static const unsigned char key[16] = { 0 };
    static const unsigned char iv[16] = { 0 };
    OSSL_PARAM params[2];
    unsigned int pad, set = 0;
    int ret = 0;

    params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, &set);
    params[1] = OSSL_PARAM_construct_end();

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(libctx, PAD_CIPHER_NAME,
                      "provider=" PAD_PROV_NAME))
        || !TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL))
        || !TEST_true(EVP_CIPHER_CTX_set_params(ctx, params))
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 0)
        || !TEST_true(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL))
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 0))
        goto err;

    /* Turning padding back on through the same route also sticks. */
    set = 1;
    if (!TEST_true(EVP_CIPHER_CTX_set_params(ctx, params))
        || !TEST_true(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL))
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 1))
        goto err;

    ret = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

/*
 * EVP_CIPHER_CTX_set_flags() records EVP_CIPH_NO_PADDING in the context
 * without telling the provider, so the next initialisation is what has to
 * carry the request down - whether or not it keeps the provider context.
 */
static int test_set_flags_no_padding_reaches_provider(void)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    static const unsigned char key[16] = { 0 };
    static const unsigned char iv[16] = { 0 };
    unsigned int pad;
    int ret = 0;

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(libctx, PAD_CIPHER_NAME,
                      "provider=" PAD_PROV_NAME))
        || !TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL))
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 1))
        goto err;

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_NO_PADDING);

    /* Re-initialising without a cipher keeps the provider context. */
    if (!TEST_true(EVP_EncryptInit_ex2(ctx, NULL, key, iv, NULL))
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 0))
        goto err;

    /* Supplying the cipher allocates a fresh one. */
    if (!TEST_true(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL))
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 0))
        goto err;

    ret = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

/*
 * Padding handed to the initialisation call as a parameter is the same
 * request as any other, so it has to survive a later initialisation too.
 */
static int test_padding_param_at_init_survives_reinit(void)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    static const unsigned char key[16] = { 0 };
    static const unsigned char iv[16] = { 0 };
    OSSL_PARAM params[2];
    unsigned int pad, set = 0;
    int ret = 0;

    params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, &set);
    params[1] = OSSL_PARAM_construct_end();

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(libctx, PAD_CIPHER_NAME,
                      "provider=" PAD_PROV_NAME))
        || !TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx, cipher, key, iv, params))
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 0))
        goto err;

    /* The cipher is supplied again, so this provider context is a new one. */
    if (!TEST_true(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL))
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 0))
        goto err;

    /* Asking for padding through the same route also sticks. */
    set = 1;
    if (!TEST_true(EVP_EncryptInit_ex2(ctx, cipher, key, iv, params))
        || !TEST_true(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL))
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 1))
        goto err;

    ret = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

/*
 * A provider that refuses the padding request fails the initialisation.  The
 * context is then unusable, so a retry has to keep failing rather than hand
 * back a context whose padding is not the one that was asked for.
 */
static int test_padding_failure_is_reported_on_retry(void)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    static const unsigned char key[16] = { 0 };
    static const unsigned char iv[16] = { 0 };
    unsigned int pad;
    int ret = 0;

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(libctx, PAD_REJECT_CIPHER_NAME,
                      "provider=" PAD_PROV_NAME))
        || !TEST_ptr(ctx = EVP_CIPHER_CTX_new()))
        goto err;

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_NO_PADDING);

    if (!TEST_false(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL)))
        goto err;

    /* The provider kept padding enabled, so the retry cannot succeed. */
    if (!TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 1)
        || !TEST_false(EVP_EncryptInit_ex2(ctx, NULL, key, iv, NULL)))
        goto err;

    ret = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

/*
 * An init that keeps the provider context has nothing to tell it about
 * padding, since the value is already there.
 */
static int test_reinit_leaves_padding_alone(void)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    static const unsigned char key[16] = { 0 };
    static const unsigned char iv[16] = { 0 };
    unsigned int pad;
    int i, count, ret = 0;

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(libctx, PAD_CIPHER_NAME,
                      "provider=" PAD_PROV_NAME))
        || !TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL))
        || !TEST_true(EVP_CIPHER_CTX_set_padding(ctx, 0)))
        goto err;

    count = pad_set_count;
    for (i = 0; i < 3; i++) {
        if (!TEST_true(EVP_EncryptInit_ex2(ctx, NULL, key, iv, NULL)))
            goto err;
    }
    if (!TEST_int_eq(pad_set_count, count)
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 0))
        goto err;

    ret = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

/*
 * Clearing the flag is the opposite request, so an init has to put the
 * provider back to padding rather than leave the earlier choice in place.
 */
static int test_clear_flags_restores_padding(void)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    static const unsigned char key[16] = { 0 };
    static const unsigned char iv[16] = { 0 };
    unsigned int pad;
    int ret = 0;

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(libctx, PAD_CIPHER_NAME,
                      "provider=" PAD_PROV_NAME))
        || !TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL))
        || !TEST_true(EVP_CIPHER_CTX_set_padding(ctx, 0))
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 0))
        goto err;

    EVP_CIPHER_CTX_clear_flags(ctx, EVP_CIPH_NO_PADDING);

    /* The provider context is kept here, so only EVP knows of the change. */
    if (!TEST_true(EVP_EncryptInit_ex2(ctx, NULL, key, iv, NULL))
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 1))
        goto err;

    ret = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

/* A copy of a context is padded exactly as the context it came from. */
static int test_copy_keeps_padding(void)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL, *copy = NULL;
    static const unsigned char key[16] = { 0 };
    static const unsigned char iv[16] = { 0 };
    unsigned int pad;
    int ret = 0;

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(libctx, PAD_CIPHER_NAME,
                      "provider=" PAD_PROV_NAME))
        || !TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_ptr(copy = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL))
        || !TEST_true(EVP_CIPHER_CTX_set_padding(ctx, 0))
        || !TEST_true(EVP_CIPHER_CTX_copy(copy, ctx))
        || !TEST_true(get_provider_padding(copy, &pad))
        || !TEST_uint_eq(pad, 0))
        goto err;

    /* Initialising the copy again keeps it, both ways round. */
    if (!TEST_true(EVP_EncryptInit_ex2(copy, NULL, key, iv, NULL))
        || !TEST_true(get_provider_padding(copy, &pad))
        || !TEST_uint_eq(pad, 0)
        || !TEST_true(EVP_EncryptInit_ex2(copy, cipher, key, iv, NULL))
        || !TEST_true(get_provider_padding(copy, &pad))
        || !TEST_uint_eq(pad, 0))
        goto err;

    ret = 1;
err:
    EVP_CIPHER_CTX_free(copy);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

/*
 * EVP_CipherInit_SKEY() carries the same padding handling, and needs a cipher
 * with key management behind it rather than the one registered above.
 */
static int test_skey_padding_survives_reinit(void)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_SKEY *skey = NULL;
    static unsigned char key[16] = { 0 };
    static const unsigned char iv[16] = { 0 };
    OSSL_PARAM params[2];
    unsigned int pad, set = 0;
    int ret = 0;

    params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, &set);
    params[1] = OSSL_PARAM_construct_end();

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(libctx, "AES-128-CBC", NULL))
        || !TEST_ptr(skey = EVP_SKEY_import_raw_key(libctx, "AES", key,
                         sizeof(key), NULL))
        || !TEST_ptr(ctx = EVP_CIPHER_CTX_new()))
        goto err;

    if (!TEST_true(EVP_CipherInit_SKEY(ctx, cipher, skey, iv, sizeof(iv), 1,
            NULL))
        || !TEST_true(EVP_CIPHER_CTX_set_padding(ctx, 0))
        || !TEST_true(EVP_CipherInit_SKEY(ctx, cipher, skey, iv, sizeof(iv), 1,
            NULL))
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 0))
        goto err;

    /* Padding handed to this init call has to be remembered as well. */
    if (!TEST_true(EVP_CIPHER_CTX_reset(ctx))
        || !TEST_true(EVP_CipherInit_SKEY(ctx, cipher, skey, iv, sizeof(iv), 1,
            params))
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 0)
        || !TEST_true(EVP_CipherInit_SKEY(ctx, cipher, skey, iv, sizeof(iv), 1,
            NULL))
        || !TEST_true(get_provider_padding(ctx, &pad))
        || !TEST_uint_eq(pad, 0))
        goto err;

    ret = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_SKEY_free(skey);
    EVP_CIPHER_free(cipher);
    return ret;
}

int setup_tests(void)
{
    if (!TEST_ptr(libctx = OSSL_LIB_CTX_new())
        || !TEST_true(OSSL_PROVIDER_add_builtin(libctx, PAD_PROV_NAME,
            pad_prov_init))
        || !TEST_ptr(padprov = OSSL_PROVIDER_load(libctx, PAD_PROV_NAME))
        || !TEST_ptr(defprov = OSSL_PROVIDER_load(libctx, "default")))
        return 0;

    ADD_TEST(test_set_padding_survives_reinit);
    ADD_TEST(test_padding_param_survives_reinit);
    ADD_TEST(test_set_flags_no_padding_reaches_provider);
    ADD_TEST(test_padding_param_at_init_survives_reinit);
    ADD_TEST(test_padding_failure_is_reported_on_retry);
    ADD_TEST(test_reinit_leaves_padding_alone);
    ADD_TEST(test_clear_flags_restores_padding);
    ADD_TEST(test_copy_keeps_padding);
    ADD_TEST(test_skey_padding_survives_reinit);
    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(defprov);
    OSSL_PROVIDER_unload(padprov);
    OSSL_LIB_CTX_free(libctx);
}
