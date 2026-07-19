/*
 * Copyright 2021-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/store.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <stdint.h>
#include "testutil.h"

static int use_dynamic_no_cache;
static int reverse_decoder_properties;
static int decoder_query_count;
static uintptr_t released_decoder_propdef;
static uintptr_t released_encoder_propdef;
static uintptr_t released_store_propdef;
static uintptr_t released_rand_dispatch;
static uintptr_t released_description[OSSL_OP__HIGHEST + 1];
static int released_algorithm_count[OSSL_OP__HIGHEST + 1];
static uintptr_t rand_parent_dispatch;
static int rand_parent_dispatch_count;
static int rand_parent_dispatch_valid;

static int dummy_decoder_decode(void *ctx, OSSL_CORE_BIO *cin, int selection,
    OSSL_CALLBACK *object_cb, void *object_cbarg,
    OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    return 0;
}

static void *dummy_decoder_newctx(void *provctx)
{
    return provctx;
}

static void dummy_decoder_freectx(void *ctx)
{
}

static const OSSL_DISPATCH dummy_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))dummy_decoder_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))dummy_decoder_freectx },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))dummy_decoder_decode },
    OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM dummy_decoders[] = {
    { "DUMMY", "provider=dummy,input=pem", dummy_decoder_functions },
    { NULL, NULL, NULL }
};

static int dummy_encoder_encode(void *ctx, OSSL_CORE_BIO *out,
    const void *obj_raw,
    const OSSL_PARAM obj_abstract[], int selection,
    OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return 0;
}

static const OSSL_DISPATCH dummy_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))dummy_encoder_encode },
    OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM dummy_encoders[] = {
    { "DUMMY", "provider=dummy,output=pem", dummy_encoder_functions },
    { NULL, NULL, NULL }
};

static void *dummy_store_open(void *provctx, const char *uri)
{
    return NULL;
}

static int dummy_store_load(void *loaderctx, OSSL_CALLBACK *object_cb,
    void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb,
    void *pw_cbarg)
{
    return 0;
}

static int dumm_store_eof(void *loaderctx)
{
    return 0;
}

static int dummy_store_close(void *loaderctx)
{
    return 0;
}

static const OSSL_DISPATCH dummy_store_functions[] = {
    { OSSL_FUNC_STORE_OPEN, (void (*)(void))dummy_store_open },
    { OSSL_FUNC_STORE_LOAD, (void (*)(void))dummy_store_load },
    { OSSL_FUNC_STORE_EOF, (void (*)(void))dumm_store_eof },
    { OSSL_FUNC_STORE_CLOSE, (void (*)(void))dummy_store_close },
    OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM dummy_store[] = {
    { "DUMMY", "provider=dummy", dummy_store_functions },
    { NULL, NULL, NULL }
};

static void *dummy_evp_newctx(void *provctx)
{
    return provctx;
}

static void dummy_evp_freectx(void *ctx)
{
}

static int dummy_digest_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 1))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 1))
        return 0;
    return 1;
}

static int dummy_digest_digest(void *provctx, const unsigned char *in,
    size_t inl, unsigned char *out, size_t *outl, size_t outsz)
{
    *outl = 0;
    return 1;
}

static const OSSL_DISPATCH dummy_digest_functions[] = {
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))dummy_digest_get_params },
    { OSSL_FUNC_DIGEST_DIGEST, (void (*)(void))dummy_digest_digest },
    OSSL_DISPATCH_END
};

static int dummy_cipher_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 1))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 1))
        return 0;
    return 1;
}

static int dummy_cipher_cipher(void *ctx, unsigned char *out, size_t *outl,
    size_t outsize, const unsigned char *in, size_t inl)
{
    *outl = 0;
    return 1;
}

static const OSSL_DISPATCH dummy_cipher_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))dummy_evp_newctx },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))dummy_cipher_cipher },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))dummy_evp_freectx },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))dummy_cipher_get_params },
    OSSL_DISPATCH_END
};

static int dummy_mac_init(void *ctx, const unsigned char *key, size_t keylen,
    const OSSL_PARAM params[])
{
    return 1;
}

static int dummy_mac_update(void *ctx, const unsigned char *in, size_t inl)
{
    return 1;
}

static int dummy_mac_final(void *ctx, unsigned char *out, size_t *outl,
    size_t outsize)
{
    *outl = 0;
    return 1;
}

static const OSSL_DISPATCH dummy_mac_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void))dummy_evp_newctx },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void))dummy_evp_freectx },
    { OSSL_FUNC_MAC_INIT, (void (*)(void))dummy_mac_init },
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void))dummy_mac_update },
    { OSSL_FUNC_MAC_FINAL, (void (*)(void))dummy_mac_final },
    OSSL_DISPATCH_END
};

static int dummy_kdf_derive(void *ctx, unsigned char *key, size_t keylen,
    const OSSL_PARAM params[])
{
    return 1;
}

static const OSSL_DISPATCH dummy_kdf_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void (*)(void))dummy_evp_newctx },
    { OSSL_FUNC_KDF_FREECTX, (void (*)(void))dummy_evp_freectx },
    { OSSL_FUNC_KDF_DERIVE, (void (*)(void))dummy_kdf_derive },
    OSSL_DISPATCH_END
};

static int dummy_keymgmt_has(const void *keydata, int selection)
{
    return 1;
}

static const OSSL_DISPATCH dummy_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))dummy_evp_newctx },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))dummy_evp_freectx },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))dummy_keymgmt_has },
    OSSL_DISPATCH_END
};

static void *dummy_skeymgmt_import(void *provctx, int selection,
    const OSSL_PARAM params[])
{
    return provctx;
}

static int dummy_skeymgmt_export(void *keydata, int selection,
    OSSL_CALLBACK *param_cb, void *cbarg)
{
    return 1;
}

static const OSSL_DISPATCH dummy_skeymgmt_functions[] = {
    { OSSL_FUNC_SKEYMGMT_FREE, (void (*)(void))dummy_evp_freectx },
    { OSSL_FUNC_SKEYMGMT_IMPORT, (void (*)(void))dummy_skeymgmt_import },
    { OSSL_FUNC_SKEYMGMT_EXPORT, (void (*)(void))dummy_skeymgmt_export },
    OSSL_DISPATCH_END
};

static void *dummy_signature_newctx(void *provctx, const char *propq)
{
    return provctx;
}

static int dummy_pkey_init(void *ctx, void *provkey,
    const OSSL_PARAM params[])
{
    return 1;
}

static int dummy_pkey_output(void *ctx, unsigned char *out, size_t *outlen,
    size_t outsize, const unsigned char *in, size_t inlen)
{
    *outlen = 0;
    return 1;
}

static const OSSL_DISPATCH dummy_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))dummy_signature_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))dummy_pkey_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))dummy_pkey_output },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))dummy_evp_freectx },
    OSSL_DISPATCH_END
};

static const OSSL_DISPATCH dummy_asym_cipher_functions[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))dummy_evp_newctx },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void))dummy_pkey_init },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))dummy_pkey_output },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))dummy_evp_freectx },
    OSSL_DISPATCH_END
};

static int dummy_kem_encapsulate(void *ctx, unsigned char *out,
    size_t *outlen, unsigned char *secret, size_t *secretlen)
{
    *outlen = 0;
    *secretlen = 0;
    return 1;
}

static int dummy_kem_decapsulate(void *ctx, unsigned char *out,
    size_t *outlen, const unsigned char *in, size_t inlen)
{
    *outlen = 0;
    return 1;
}

static const OSSL_DISPATCH dummy_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))dummy_evp_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))dummy_pkey_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))dummy_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))dummy_pkey_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))dummy_kem_decapsulate },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))dummy_evp_freectx },
    OSSL_DISPATCH_END
};

static int dummy_keyexch_derive(void *ctx, unsigned char *secret,
    size_t *secretlen, size_t outlen)
{
    *secretlen = 0;
    return 1;
}

static const OSSL_DISPATCH dummy_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))dummy_evp_newctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))dummy_pkey_init },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))dummy_keyexch_derive },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))dummy_evp_freectx },
    OSSL_DISPATCH_END
};

static void *dummy_rand_newctx(void *provctx, void *parent,
    const OSSL_DISPATCH *parent_calls)
{
    const OSSL_DISPATCH *fns;

    if (use_dynamic_no_cache && parent_calls != NULL) {
        rand_parent_dispatch = (uintptr_t)parent_calls;
        rand_parent_dispatch_count++;
        if (rand_parent_dispatch == released_rand_dispatch)
            return NULL;

        for (fns = parent_calls; fns->function_id != 0; fns++) {
            if (fns->function_id == OSSL_FUNC_RAND_GENERATE)
                rand_parent_dispatch_valid = 1;
        }
    }

    return provctx;
}

static void dummy_rand_freectx(void *vctx)
{
}

static int dummy_rand_instantiate(void *vdrbg, unsigned int strength,
    int prediction_resistance,
    const unsigned char *pstr, size_t pstr_len,
    const OSSL_PARAM params[])
{
    return 1;
}

static int dummy_rand_uninstantiate(void *vdrbg)
{
    return 1;
}

static int dummy_rand_generate(void *vctx, unsigned char *out, size_t outlen,
    unsigned int strength, int prediction_resistance,
    const unsigned char *addin, size_t addin_len)
{
    size_t i;

    for (i = 0; i < outlen; i++)
        out[i] = (unsigned char)(i & 0xff);

    return 1;
}

static const OSSL_PARAM *dummy_rand_gettable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

static int dummy_rand_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, INT_MAX))
        return 0;

    return 1;
}

static int dummy_rand_enable_locking(void *vtest)
{
    return 1;
}

static int dummy_rand_lock(void *vtest)
{
    return 1;
}

static void dummy_rand_unlock(void *vtest)
{
}

static const OSSL_DISPATCH dummy_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))dummy_rand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))dummy_rand_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))dummy_rand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))dummy_rand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))dummy_rand_generate },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
        (void (*)(void))dummy_rand_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))dummy_rand_get_ctx_params },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))dummy_rand_enable_locking },
    { OSSL_FUNC_RAND_LOCK, (void (*)(void))dummy_rand_lock },
    { OSSL_FUNC_RAND_UNLOCK, (void (*)(void))dummy_rand_unlock },
    OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM dummy_rand[] = {
    { "DUMMY", "provider=dummy", dummy_rand_functions },
    { NULL, NULL, NULL }
};

static OSSL_DISPATCH *dummy_dynamic_dispatch(const OSSL_DISPATCH *fns)
{
    const OSSL_DISPATCH *p;
    size_t n;

    for (p = fns; p->function_id != 0; p++)
        continue;

    n = (size_t)(p - fns) + 1;
    return OPENSSL_memdup(fns, n * sizeof(*fns));
}

static OSSL_ALGORITHM *dummy_dynamic_algorithm(const char *names,
    const char *props, const OSSL_DISPATCH *fns, const char *description)
{
    OSSL_ALGORITHM *algs = OPENSSL_zalloc(2 * sizeof(*algs));

    if (algs == NULL)
        return NULL;

    algs[0].algorithm_names = OPENSSL_strdup(names);
    algs[0].property_definition = OPENSSL_strdup(props);
    algs[0].implementation = dummy_dynamic_dispatch(fns);
    algs[0].algorithm_description = OPENSSL_strdup(description);

    if (algs[0].algorithm_names == NULL
        || algs[0].property_definition == NULL
        || algs[0].implementation == NULL
        || algs[0].algorithm_description == NULL) {
        OPENSSL_free((char *)algs[0].algorithm_names);
        OPENSSL_free((char *)algs[0].property_definition);
        OPENSSL_free((OSSL_DISPATCH *)algs[0].implementation);
        OPENSSL_free((char *)algs[0].algorithm_description);
        OPENSSL_free(algs);
        return NULL;
    }

    return algs;
}

static void dummy_free_dynamic_algorithm(const OSSL_ALGORITHM *algs)
{
    OSSL_ALGORITHM *a = (OSSL_ALGORITHM *)algs;

    if (a == NULL)
        return;

    OPENSSL_free((char *)a[0].algorithm_names);
    OPENSSL_free((char *)a[0].property_definition);
    OPENSSL_free((OSSL_DISPATCH *)a[0].implementation);
    OPENSSL_free((char *)a[0].algorithm_description);
    OPENSSL_free(a);
}

static const OSSL_ALGORITHM *dummy_query(void *provctx, int operation_id,
    int *no_cache)
{
    *no_cache = 0;
    if (use_dynamic_no_cache) {
        switch (operation_id) {
        case OSSL_OP_DIGEST:
            *no_cache = 1;
            return dummy_dynamic_algorithm("DUMMY", "provider=dummy",
                dummy_digest_functions, "dynamic dummy digest");
        case OSSL_OP_CIPHER:
            *no_cache = 1;
            return dummy_dynamic_algorithm("DUMMY", "provider=dummy",
                dummy_cipher_functions, "dynamic dummy cipher");
        case OSSL_OP_MAC:
            *no_cache = 1;
            return dummy_dynamic_algorithm("DUMMY", "provider=dummy",
                dummy_mac_functions, "dynamic dummy mac");
        case OSSL_OP_KDF:
            *no_cache = 1;
            return dummy_dynamic_algorithm("DUMMY", "provider=dummy",
                dummy_kdf_functions, "dynamic dummy kdf");
        case OSSL_OP_DECODER:
            *no_cache = 1;
            decoder_query_count++;
            return dummy_dynamic_algorithm("DUMMY:PEM",
                reverse_decoder_properties ? "input=pem,provider=dummy"
                                           : "provider=dummy,input=pem",
                dummy_decoder_functions, "dynamic dummy decoder");
        case OSSL_OP_ENCODER:
            *no_cache = 1;
            return dummy_dynamic_algorithm("DUMMY",
                "provider=dummy,output=pem", dummy_encoder_functions,
                "dynamic dummy encoder");
        case OSSL_OP_STORE:
            *no_cache = 1;
            return dummy_dynamic_algorithm("DUMMY", "provider=dummy",
                dummy_store_functions, "dynamic dummy store");
        case OSSL_OP_RAND:
            *no_cache = 1;
            return dummy_dynamic_algorithm("DUMMY", "provider=dummy",
                dummy_rand_functions, "dynamic dummy rand");
        case OSSL_OP_KEYMGMT:
            *no_cache = 1;
            return dummy_dynamic_algorithm("DUMMY", "provider=dummy",
                dummy_keymgmt_functions, "dynamic dummy keymgmt");
        case OSSL_OP_KEYEXCH:
            *no_cache = 1;
            return dummy_dynamic_algorithm("DUMMY", "provider=dummy",
                dummy_keyexch_functions, "dynamic dummy keyexch");
        case OSSL_OP_SIGNATURE:
            *no_cache = 1;
            return dummy_dynamic_algorithm("DUMMY", "provider=dummy",
                dummy_signature_functions, "dynamic dummy signature");
        case OSSL_OP_ASYM_CIPHER:
            *no_cache = 1;
            return dummy_dynamic_algorithm("DUMMY", "provider=dummy",
                dummy_asym_cipher_functions, "dynamic dummy asym cipher");
        case OSSL_OP_KEM:
            *no_cache = 1;
            return dummy_dynamic_algorithm("DUMMY", "provider=dummy",
                dummy_kem_functions, "dynamic dummy kem");
        case OSSL_OP_SKEYMGMT:
            *no_cache = 1;
            return dummy_dynamic_algorithm("DUMMY", "provider=dummy",
                dummy_skeymgmt_functions, "dynamic dummy skeymgmt");
        }
    }

    switch (operation_id) {
    case OSSL_OP_DECODER:
        decoder_query_count++;
        return dummy_decoders;
    case OSSL_OP_ENCODER:
        return dummy_encoders;
    case OSSL_OP_STORE:
        return dummy_store;
    case OSSL_OP_RAND:
        return dummy_rand;
    }
    return NULL;
}

static void dummy_unquery(void *provctx, int operation_id,
    const OSSL_ALGORITHM *algs)
{
    if (!use_dynamic_no_cache || algs == NULL)
        return;

    if (operation_id < 0 || operation_id > OSSL_OP__HIGHEST)
        return;

    released_description[operation_id]
        = (uintptr_t)algs[0].algorithm_description;
    released_algorithm_count[operation_id]++;

    switch (operation_id) {
    case OSSL_OP_DECODER:
        released_decoder_propdef = (uintptr_t)algs[0].property_definition;
        break;
    case OSSL_OP_ENCODER:
        released_encoder_propdef = (uintptr_t)algs[0].property_definition;
        break;
    case OSSL_OP_STORE:
        released_store_propdef = (uintptr_t)algs[0].property_definition;
        break;
    case OSSL_OP_RAND:
        released_rand_dispatch = (uintptr_t)algs[0].implementation;
        break;
    default:
        break;
    }

    dummy_free_dynamic_algorithm(algs);
}

static const OSSL_DISPATCH dummy_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))dummy_query },
    { OSSL_FUNC_PROVIDER_UNQUERY_OPERATION, (void (*)(void))dummy_unquery },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))OSSL_LIB_CTX_free },
    OSSL_DISPATCH_END
};

static int dummy_provider_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out,
    void **provctx)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new_child(handle, in);
    unsigned char buf[32];

    *provctx = (void *)libctx;
    *out = dummy_dispatch_table;

    /*
     * Do some work using the child libctx, to make sure this is possible from
     * inside the init function.
     */
    if (RAND_bytes_ex(libctx, buf, sizeof(buf), 0) <= 0)
        return 0;

    return 1;
}

/*
 * Try fetching and freeing various things.
 * Test 0: Decoder
 * Test 1: Encoder
 * Test 2: Store loader
 * Test 3: EVP_RAND
 * Test 4-7: As above, but additionally with a query string
 */
static int fetch_test(int tst)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *dummyprov = NULL;
    OSSL_PROVIDER *nullprov = NULL;
    OSSL_DECODER *decoder = NULL;
    OSSL_ENCODER *encoder = NULL;
    OSSL_STORE_LOADER *loader = NULL;
    int testresult = 0;
    unsigned char buf[32];
    int query = tst > 3;

    if (!TEST_ptr(libctx))
        goto err;

    if (!TEST_true(OSSL_PROVIDER_add_builtin(libctx, "dummy-prov",
            dummy_provider_init))
        || !TEST_ptr(nullprov = OSSL_PROVIDER_load(libctx, "default"))
        || !TEST_ptr(dummyprov = OSSL_PROVIDER_load(libctx, "dummy-prov")))
        goto err;

    switch (tst % 4) {
    case 0:
        decoder = OSSL_DECODER_fetch(libctx, "DUMMY",
            query ? "provider=dummy" : NULL);
        if (!TEST_ptr(decoder))
            goto err;
        break;
    case 1:
        encoder = OSSL_ENCODER_fetch(libctx, "DUMMY",
            query ? "provider=dummy" : NULL);
        if (!TEST_ptr(encoder))
            goto err;
        break;
    case 2:
        loader = OSSL_STORE_LOADER_fetch(libctx, "DUMMY",
            query ? "provider=dummy" : NULL);
        if (!TEST_ptr(loader))
            goto err;
        break;
    case 3:
        if (!TEST_true(RAND_set_DRBG_type(libctx, "DUMMY",
                query ? "provider=dummy" : NULL,
                NULL, NULL))
            || !TEST_int_ge(RAND_bytes_ex(libctx, buf, sizeof(buf), 0), 1))
            goto err;
        break;
    default:
        goto err;
    }

    testresult = 1;
err:
    OSSL_DECODER_free(decoder);
    OSSL_ENCODER_free(encoder);
    OSSL_STORE_LOADER_free(loader);
    OSSL_PROVIDER_unload(dummyprov);
    OSSL_PROVIDER_unload(nullprov);
    OSSL_LIB_CTX_free(libctx);
    return testresult;
}

static int fetch_dynamic_no_cache_test(int tst)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *dummyprov = NULL;
    OSSL_PROVIDER *defaultprov = NULL;
    OSSL_DECODER *decoder = NULL;
    OSSL_ENCODER *encoder = NULL;
    OSSL_STORE_LOADER *loader = NULL;
    EVP_RAND *rand = NULL;
    EVP_RAND_CTX *parent_rand_ctx = NULL;
    EVP_RAND_CTX *rand_ctx = NULL;
    const char *props = NULL;
    const char *description = NULL;
    int testresult = 0;

    if (!TEST_ptr(libctx))
        goto err;

    use_dynamic_no_cache = 1;
    reverse_decoder_properties = 0;
    decoder_query_count = 0;
    released_decoder_propdef = 0;
    released_encoder_propdef = 0;
    released_store_propdef = 0;
    released_rand_dispatch = 0;
    memset(released_description, 0, sizeof(released_description));
    memset(released_algorithm_count, 0, sizeof(released_algorithm_count));
    rand_parent_dispatch = 0;
    rand_parent_dispatch_count = 0;
    rand_parent_dispatch_valid = 0;

    if (!TEST_true(OSSL_PROVIDER_add_builtin(libctx, "dummy-prov",
            dummy_provider_init))
        || !TEST_ptr(defaultprov = OSSL_PROVIDER_load(libctx, "default"))
        || !TEST_ptr(dummyprov = OSSL_PROVIDER_load(libctx, "dummy-prov")))
        goto err;

    switch (tst) {
    case 0:
        if (!TEST_ptr(decoder = OSSL_DECODER_fetch(libctx, "DUMMY",
                          "provider=dummy")))
            goto err;
        props = OSSL_DECODER_get0_properties(decoder);
        description = OSSL_DECODER_get0_description(decoder);
        if (!TEST_int_gt(released_algorithm_count[OSSL_OP_DECODER], 0)
            || !TEST_uint64_t_ne((uint64_t)(uintptr_t)props,
                (uint64_t)released_decoder_propdef)
            || !TEST_uint64_t_ne((uint64_t)(uintptr_t)description,
                (uint64_t)released_description[OSSL_OP_DECODER])
            || !TEST_str_eq(props, "provider=dummy,input=pem")
            || !TEST_str_eq(description, "dynamic dummy decoder"))
            goto err;
        break;
    case 1:
        if (!TEST_ptr(encoder = OSSL_ENCODER_fetch(libctx, "DUMMY",
                          "provider=dummy")))
            goto err;
        props = OSSL_ENCODER_get0_properties(encoder);
        description = OSSL_ENCODER_get0_description(encoder);
        if (!TEST_int_gt(released_algorithm_count[OSSL_OP_ENCODER], 0)
            || !TEST_uint64_t_ne((uint64_t)(uintptr_t)props,
                (uint64_t)released_encoder_propdef)
            || !TEST_uint64_t_ne((uint64_t)(uintptr_t)description,
                (uint64_t)released_description[OSSL_OP_ENCODER])
            || !TEST_str_eq(props, "provider=dummy,output=pem")
            || !TEST_str_eq(description, "dynamic dummy encoder"))
            goto err;
        break;
    case 2:
        if (!TEST_ptr(loader = OSSL_STORE_LOADER_fetch(libctx, "DUMMY",
                          "provider=dummy")))
            goto err;
        props = OSSL_STORE_LOADER_get0_properties(loader);
        description = OSSL_STORE_LOADER_get0_description(loader);
        if (!TEST_int_gt(released_algorithm_count[OSSL_OP_STORE], 0)
            || !TEST_uint64_t_ne((uint64_t)(uintptr_t)props,
                (uint64_t)released_store_propdef)
            || !TEST_uint64_t_ne((uint64_t)(uintptr_t)description,
                (uint64_t)released_description[OSSL_OP_STORE])
            || !TEST_str_eq(props, "provider=dummy")
            || !TEST_str_eq(description, "dynamic dummy store"))
            goto err;
        break;
    case 3:
        if (!TEST_ptr(rand = EVP_RAND_fetch(libctx, "DUMMY",
                          "provider=dummy")))
            goto err;
        description = EVP_RAND_get0_description(rand);
        if (!TEST_int_gt(released_algorithm_count[OSSL_OP_RAND], 0)
            || !TEST_uint64_t_ne((uint64_t)(uintptr_t)description,
                (uint64_t)released_description[OSSL_OP_RAND])
            || !TEST_str_eq(description, "dynamic dummy rand")
            || !TEST_ptr(parent_rand_ctx = EVP_RAND_CTX_new(rand, NULL))
            || !TEST_ptr(rand_ctx = EVP_RAND_CTX_new(rand, parent_rand_ctx))
            || !TEST_int_gt(rand_parent_dispatch_count, 0)
            || !TEST_int_eq(rand_parent_dispatch_valid, 1)
            || !TEST_uint64_t_ne((uint64_t)rand_parent_dispatch,
                (uint64_t)released_rand_dispatch))
            goto err;
        break;
    default:
        goto err;
    }

    testresult = 1;
err:
    OSSL_DECODER_free(decoder);
    OSSL_ENCODER_free(encoder);
    OSSL_STORE_LOADER_free(loader);
    EVP_RAND_CTX_free(rand_ctx);
    EVP_RAND_CTX_free(parent_rand_ctx);
    EVP_RAND_free(rand);
    OSSL_PROVIDER_unload(dummyprov);
    OSSL_PROVIDER_unload(defaultprov);
    OSSL_LIB_CTX_free(libctx);
    use_dynamic_no_cache = 0;
    reverse_decoder_properties = 0;
    return testresult;
}

static const struct {
    int operation_id;
    const char *description;
} dynamic_evp_description_tests[] = {
    { OSSL_OP_DIGEST, "dynamic dummy digest" },
    { OSSL_OP_CIPHER, "dynamic dummy cipher" },
    { OSSL_OP_MAC, "dynamic dummy mac" },
    { OSSL_OP_KDF, "dynamic dummy kdf" },
    { OSSL_OP_KEYMGMT, "dynamic dummy keymgmt" },
    { OSSL_OP_SKEYMGMT, "dynamic dummy skeymgmt" },
    { OSSL_OP_SIGNATURE, "dynamic dummy signature" },
    { OSSL_OP_ASYM_CIPHER, "dynamic dummy asym cipher" },
    { OSSL_OP_KEM, "dynamic dummy kem" },
    { OSSL_OP_KEYEXCH, "dynamic dummy keyexch" }
};

static int fetch_dynamic_evp_description_test(int tst)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *dummyprov = NULL;
    OSSL_PROVIDER *defaultprov = NULL;
    EVP_MD *md = NULL;
    EVP_CIPHER *cipher = NULL;
    EVP_MAC *mac = NULL;
    EVP_KDF *kdf = NULL;
    EVP_KEYMGMT *keymgmt = NULL;
    EVP_SKEYMGMT *skeymgmt = NULL;
    EVP_SIGNATURE *signature = NULL;
    EVP_ASYM_CIPHER *asym_cipher = NULL;
    EVP_KEM *kem = NULL;
    EVP_KEYEXCH *keyexch = NULL;
    const char *description = NULL;
    int operation_id = dynamic_evp_description_tests[tst].operation_id;
    int testresult = 0;

    if (!TEST_ptr(libctx))
        goto err;

    use_dynamic_no_cache = 1;
    reverse_decoder_properties = 0;
    decoder_query_count = 0;
    memset(released_description, 0, sizeof(released_description));
    memset(released_algorithm_count, 0, sizeof(released_algorithm_count));

    if (!TEST_true(OSSL_PROVIDER_add_builtin(libctx, "dummy-prov",
            dummy_provider_init))
        || !TEST_ptr(defaultprov = OSSL_PROVIDER_load(libctx, "default"))
        || !TEST_ptr(dummyprov = OSSL_PROVIDER_load(libctx, "dummy-prov")))
        goto err;

    switch (operation_id) {
    case OSSL_OP_DIGEST:
        if (!TEST_ptr(md = EVP_MD_fetch(libctx, "DUMMY", "provider=dummy")))
            goto err;
        description = EVP_MD_get0_description(md);
        break;
    case OSSL_OP_CIPHER:
        if (!TEST_ptr(cipher = EVP_CIPHER_fetch(libctx, "DUMMY",
                          "provider=dummy")))
            goto err;
        description = EVP_CIPHER_get0_description(cipher);
        break;
    case OSSL_OP_MAC:
        if (!TEST_ptr(mac = EVP_MAC_fetch(libctx, "DUMMY", "provider=dummy")))
            goto err;
        description = EVP_MAC_get0_description(mac);
        break;
    case OSSL_OP_KDF:
        if (!TEST_ptr(kdf = EVP_KDF_fetch(libctx, "DUMMY", "provider=dummy")))
            goto err;
        description = EVP_KDF_get0_description(kdf);
        break;
    case OSSL_OP_KEYMGMT:
        if (!TEST_ptr(keymgmt = EVP_KEYMGMT_fetch(libctx, "DUMMY",
                          "provider=dummy")))
            goto err;
        description = EVP_KEYMGMT_get0_description(keymgmt);
        break;
    case OSSL_OP_SKEYMGMT:
        if (!TEST_ptr(skeymgmt = EVP_SKEYMGMT_fetch(libctx, "DUMMY",
                          "provider=dummy")))
            goto err;
        description = EVP_SKEYMGMT_get0_description(skeymgmt);
        break;
    case OSSL_OP_SIGNATURE:
        if (!TEST_ptr(signature = EVP_SIGNATURE_fetch(libctx, "DUMMY",
                          "provider=dummy")))
            goto err;
        description = EVP_SIGNATURE_get0_description(signature);
        break;
    case OSSL_OP_ASYM_CIPHER:
        if (!TEST_ptr(asym_cipher = EVP_ASYM_CIPHER_fetch(libctx, "DUMMY",
                          "provider=dummy")))
            goto err;
        description = EVP_ASYM_CIPHER_get0_description(asym_cipher);
        break;
    case OSSL_OP_KEM:
        if (!TEST_ptr(kem = EVP_KEM_fetch(libctx, "DUMMY", "provider=dummy")))
            goto err;
        description = EVP_KEM_get0_description(kem);
        break;
    case OSSL_OP_KEYEXCH:
        if (!TEST_ptr(keyexch = EVP_KEYEXCH_fetch(libctx, "DUMMY",
                          "provider=dummy")))
            goto err;
        description = EVP_KEYEXCH_get0_description(keyexch);
        break;
    default:
        goto err;
    }

    if (!TEST_int_gt(released_algorithm_count[operation_id], 0)
        || !TEST_uint64_t_ne((uint64_t)(uintptr_t)description,
            (uint64_t)released_description[operation_id])
        || !TEST_str_eq(description,
            dynamic_evp_description_tests[tst].description))
        goto err;

    testresult = 1;
err:
    EVP_MD_free(md);
    EVP_CIPHER_free(cipher);
    EVP_MAC_free(mac);
    EVP_KDF_free(kdf);
    EVP_KEYMGMT_free(keymgmt);
    EVP_SKEYMGMT_free(skeymgmt);
    EVP_SIGNATURE_free(signature);
    EVP_ASYM_CIPHER_free(asym_cipher);
    EVP_KEM_free(kem);
    EVP_KEYEXCH_free(keyexch);
    OSSL_PROVIDER_unload(dummyprov);
    OSSL_PROVIDER_unload(defaultprov);
    OSSL_LIB_CTX_free(libctx);
    use_dynamic_no_cache = 0;
    return testresult;
}

static int decoder_dynamic_no_cache_add_extra_test(void)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *dummyprov = NULL;
    OSSL_PROVIDER *defaultprov = NULL;
    OSSL_DECODER *decoder = NULL;
    OSSL_DECODER_CTX *decoder_ctx = NULL;
    int query_count;
    int testresult = 0;

    if (!TEST_ptr(libctx))
        goto err;

    use_dynamic_no_cache = 1;
    reverse_decoder_properties = 0;
    decoder_query_count = 0;
    memset(released_description, 0, sizeof(released_description));
    memset(released_algorithm_count, 0, sizeof(released_algorithm_count));

    if (!TEST_true(OSSL_PROVIDER_add_builtin(libctx, "dummy-prov",
            dummy_provider_init))
        || !TEST_ptr(defaultprov = OSSL_PROVIDER_load(libctx, "default"))
        || !TEST_ptr(dummyprov = OSSL_PROVIDER_load(libctx, "dummy-prov"))
        || !TEST_ptr(decoder = OSSL_DECODER_fetch(libctx, "DUMMY",
                         "provider=dummy"))
        || !TEST_ptr(decoder_ctx = OSSL_DECODER_CTX_new())
        || !TEST_true(OSSL_DECODER_CTX_add_decoder(decoder_ctx, decoder))
        || !TEST_int_eq(OSSL_DECODER_CTX_get_num_decoders(decoder_ctx), 1))
        goto err;

    reverse_decoder_properties = 1;
    if (!TEST_true(OSSL_DECODER_CTX_add_extra(decoder_ctx, libctx,
            "provider=dummy"))
        || !TEST_int_gt(decoder_query_count, 1)
        || !TEST_int_eq(OSSL_DECODER_CTX_get_num_decoders(decoder_ctx), 1))
        goto err;

    query_count = decoder_query_count;
    use_dynamic_no_cache = 0;
    if (!TEST_true(OSSL_DECODER_CTX_add_extra(decoder_ctx, libctx,
            "provider=dummy"))
        || !TEST_int_gt(decoder_query_count, query_count)
        || !TEST_int_eq(OSSL_DECODER_CTX_get_num_decoders(decoder_ctx), 1))
        goto err;

    testresult = 1;
err:
    OSSL_DECODER_CTX_free(decoder_ctx);
    OSSL_DECODER_free(decoder);
    OSSL_PROVIDER_unload(dummyprov);
    OSSL_PROVIDER_unload(defaultprov);
    OSSL_LIB_CTX_free(libctx);
    use_dynamic_no_cache = 0;
    reverse_decoder_properties = 0;
    return testresult;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(fetch_test, 8);
    ADD_ALL_TESTS(fetch_dynamic_no_cache_test, 4);
    ADD_ALL_TESTS(fetch_dynamic_evp_description_test,
        OSSL_NELEM(dynamic_evp_description_tests));
    ADD_TEST(decoder_dynamic_no_cache_add_extra_test);

    return 1;
}
