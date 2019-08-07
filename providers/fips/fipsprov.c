/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/evp.h>

/* TODO(3.0): Needed for dummy_evp_call(). To be removed */
#include <openssl/sha.h>
#include <openssl/rand_drbg.h>
#include <openssl/ec.h>

#include "internal/cryptlib.h"
#include "internal/property.h"
#include "internal/evp_int.h"
#include "internal/provider_algs.h"
#include "internal/provider_ctx.h"
#include "internal/providercommon.h"

extern OSSL_core_thread_start_fn *c_thread_start;

/*
 * TODO(3.0): Should these be stored in the provider side provctx? Could they
 * ever be different from one init to the next? Unfortunately we can't do this
 * at the moment because c_put_error/c_add_error_vdata do not provide
 * us with the OPENSSL_CTX as a parameter.
 */
/* Functions provided by the core */
static OSSL_core_get_param_types_fn *c_get_param_types;
static OSSL_core_get_params_fn *c_get_params;
OSSL_core_thread_start_fn *c_thread_start;
static OSSL_core_new_error_fn *c_new_error;
static OSSL_core_set_error_debug_fn *c_set_error_debug;
static OSSL_core_vset_error_fn *c_vset_error;
static OSSL_CRYPTO_malloc_fn *c_CRYPTO_malloc;
static OSSL_CRYPTO_zalloc_fn *c_CRYPTO_zalloc;
static OSSL_CRYPTO_free_fn *c_CRYPTO_free;
static OSSL_CRYPTO_clear_free_fn *c_CRYPTO_clear_free;
static OSSL_CRYPTO_realloc_fn *c_CRYPTO_realloc;
static OSSL_CRYPTO_clear_realloc_fn *c_CRYPTO_clear_realloc;
static OSSL_CRYPTO_secure_malloc_fn *c_CRYPTO_secure_malloc;
static OSSL_CRYPTO_secure_zalloc_fn *c_CRYPTO_secure_zalloc;
static OSSL_CRYPTO_secure_free_fn *c_CRYPTO_secure_free;
static OSSL_CRYPTO_secure_clear_free_fn *c_CRYPTO_secure_clear_free;
static OSSL_CRYPTO_secure_allocated_fn *c_CRYPTO_secure_allocated;

typedef struct fips_global_st {
    const OSSL_PROVIDER *prov;
} FIPS_GLOBAL;

static void *fips_prov_ossl_ctx_new(OPENSSL_CTX *libctx)
{
    FIPS_GLOBAL *fgbl = OPENSSL_zalloc(sizeof(*fgbl));

    return fgbl;
}

static void fips_prov_ossl_ctx_free(void *fgbl)
{
    OPENSSL_free(fgbl);
}

static const OPENSSL_CTX_METHOD fips_prov_ossl_ctx_method = {
    fips_prov_ossl_ctx_new,
    fips_prov_ossl_ctx_free,
};


/* Parameters we provide to the core */
static const OSSL_PARAM fips_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_END
};

/* TODO(3.0): To be removed */
static int dummy_evp_call(void *provctx)
{
    OPENSSL_CTX *libctx = PROV_LIBRARY_CONTEXT_OF(provctx);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_MD *sha256 = EVP_MD_fetch(libctx, "SHA256", NULL);
    char msg[] = "Hello World!";
    const unsigned char exptd[] = {
        0x7f, 0x83, 0xb1, 0x65, 0x7f, 0xf1, 0xfc, 0x53, 0xb9, 0x2d, 0xc1, 0x81,
        0x48, 0xa1, 0xd6, 0x5d, 0xfc, 0x2d, 0x4b, 0x1f, 0xa3, 0xd6, 0x77, 0x28,
        0x4a, 0xdd, 0xd2, 0x00, 0x12, 0x6d, 0x90, 0x69
    };
    unsigned int dgstlen = 0;
    unsigned char dgst[SHA256_DIGEST_LENGTH];
    int ret = 0;
    BN_CTX *bnctx = NULL;
    BIGNUM *a = NULL, *b = NULL;
    unsigned char randbuf[128];
    RAND_DRBG *drbg = OPENSSL_CTX_get0_public_drbg(libctx);
#ifndef OPENSSL_NO_EC
    EC_KEY *key = NULL;
#endif

    if (ctx == NULL || sha256 == NULL || drbg == NULL)
        goto err;

    if (!EVP_DigestInit_ex(ctx, sha256, NULL))
        goto err;
    if (!EVP_DigestUpdate(ctx, msg, sizeof(msg) - 1))
        goto err;
    if (!EVP_DigestFinal(ctx, dgst, &dgstlen))
        goto err;
    if (dgstlen != sizeof(exptd) || memcmp(dgst, exptd, sizeof(exptd)) != 0)
        goto err;

    bnctx = BN_CTX_new_ex(libctx);
    if (bnctx == NULL)
        goto err;
    BN_CTX_start(bnctx);
    a = BN_CTX_get(bnctx);
    b = BN_CTX_get(bnctx);
    if (b == NULL)
        goto err;
    BN_zero(a);
    if (!BN_one(b)
        || !BN_add(a, a, b)
        || BN_cmp(a, b) != 0)
        goto err;

    if (RAND_DRBG_bytes(drbg, randbuf, sizeof(randbuf)) <= 0)
        goto err;

    if (!BN_rand_ex(a, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, bnctx))
        goto err;

#ifndef OPENSSL_NO_EC
    /* Do some dummy EC calls */
    key = EC_KEY_new_by_curve_name_ex(libctx, NID_X9_62_prime256v1);
    if (key == NULL)
        goto err;

    if (!EC_KEY_generate_key(key))
        goto err;
#endif

    ret = 1;
 err:
    BN_CTX_end(bnctx);
    BN_CTX_free(bnctx);

    EVP_MD_CTX_free(ctx);
    EVP_MD_meth_free(sha256);

#ifndef OPENSSL_NO_EC
    EC_KEY_free(key);
#endif
    return ret;
}

static const OSSL_PARAM *fips_get_param_types(const OSSL_PROVIDER *prov)
{
    return fips_param_types;
}

static int fips_get_params(const OSSL_PROVIDER *prov, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL FIPS Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;

    return 1;
}

/* FIPS specific version of the function of the same name in provlib.c */
const char *ossl_prov_util_nid_to_name(int nid)
{
    /* We don't have OBJ_nid2n() in FIPS_MODE so we have an explicit list */

    switch (nid) {
    /* Digests */
    case NID_sha1:
        return "SHA224";
    case NID_sha224:
        return "SHA224";
    case NID_sha256:
        return "SHA256";
    case NID_sha384:
        return "SHA384";
    case NID_sha512:
        return "SHA512";
    case NID_sha512_224:
        return "SHA512-224";
    case NID_sha512_256:
        return "SHA512-256";
    case NID_sha3_224:
        return "SHA3-224";
    case NID_sha3_256:
        return "SHA3-256";
    case NID_sha3_384:
        return "SHA3-384";
    case NID_sha3_512:
        return "SHA3-512";

    /* Ciphers */
    case NID_aes_256_ecb:
        return "AES-256-ECB";
    case NID_aes_192_ecb:
        return "AES-192-ECB";
    case NID_aes_128_ecb:
        return "AES-128-ECB";
    case NID_aes_256_cbc:
        return "AES-256-CBC";
    case NID_aes_192_cbc:
        return "AES-192-CBC";
    case NID_aes_128_cbc:
        return "AES-128-CBC";
    case NID_aes_256_ctr:
        return "AES-256-CTR";
    case NID_aes_192_ctr:
        return "AES-192-CTR";
    case NID_aes_128_ctr:
        return "AES-128-CTR";
    }

    return NULL;
}

static const OSSL_ALGORITHM fips_digests[] = {
    { "SHA1", "fips=yes", sha1_functions },
    { "SHA224", "fips=yes", sha224_functions },
    { "SHA256", "fips=yes", sha256_functions },
    { "SHA384", "fips=yes", sha384_functions },
    { "SHA512", "fips=yes", sha512_functions },
    { "SHA512-224", "fips=yes", sha512_224_functions },
    { "SHA512-256", "fips=yes", sha512_256_functions },
    { "SHA3-224", "fips=yes", sha3_224_functions },
    { "SHA3-256", "fips=yes", sha3_256_functions },
    { "SHA3-384", "fips=yes", sha3_384_functions },
    { "SHA3-512", "fips=yes", sha3_512_functions },
    { "KMAC128", "fips=yes", keccak_kmac_128_functions },
    { "KMAC256", "fips=yes", keccak_kmac_256_functions },

    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_ciphers[] = {
    { "AES-256-ECB", "fips=yes", aes256ecb_functions },
    { "AES-192-ECB", "fips=yes", aes192ecb_functions },
    { "AES-128-ECB", "fips=yes", aes128ecb_functions },
    { "AES-256-CBC", "fips=yes", aes256cbc_functions },
    { "AES-192-CBC", "fips=yes", aes192cbc_functions },
    { "AES-128-CBC", "fips=yes", aes128cbc_functions },
    { "AES-256-CTR", "fips=yes", aes256ctr_functions },
    { "AES-192-CTR", "fips=yes", aes192ctr_functions },
    { "AES-128-CTR", "fips=yes", aes128ctr_functions },
    { "id-aes256-GCM", "fips=yes", aes256gcm_functions },
    { "id-aes192-GCM", "fips=yes", aes192gcm_functions },
    { "id-aes128-GCM", "fips=yes", aes128gcm_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *fips_query(OSSL_PROVIDER *prov,
                                         int operation_id,
                                         int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return fips_digests;
    case OSSL_OP_CIPHER:
        return fips_ciphers;
    }
    return NULL;
}

/* Functions we provide to the core */
static const OSSL_DISPATCH fips_dispatch_table[] = {
    /*
     * To release our resources we just need to free the OPENSSL_CTX so we just
     * use OPENSSL_CTX_free directly as our teardown function
     */
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))OPENSSL_CTX_free },
    { OSSL_FUNC_PROVIDER_GET_PARAM_TYPES, (void (*)(void))fips_get_param_types },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))fips_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fips_query },
    { 0, NULL }
};

/* Functions we provide to ourself */
static const OSSL_DISPATCH intern_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fips_query },
    { 0, NULL }
};


int OSSL_provider_init(const OSSL_PROVIDER *provider,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    FIPS_GLOBAL *fgbl;
    OPENSSL_CTX *ctx;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_PARAM_TYPES:
            c_get_param_types = OSSL_get_core_get_param_types(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_get_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_THREAD_START:
            c_thread_start = OSSL_get_core_thread_start(in);
            break;
        case OSSL_FUNC_CORE_NEW_ERROR:
            c_new_error = OSSL_get_core_new_error(in);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            c_set_error_debug = OSSL_get_core_set_error_debug(in);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            c_vset_error = OSSL_get_core_vset_error(in);
            break;
        case OSSL_FUNC_CRYPTO_MALLOC:
            c_CRYPTO_malloc = OSSL_get_CRYPTO_malloc(in);
            break;
        case OSSL_FUNC_CRYPTO_ZALLOC:
            c_CRYPTO_zalloc = OSSL_get_CRYPTO_zalloc(in);
            break;
        case OSSL_FUNC_CRYPTO_FREE:
            c_CRYPTO_free = OSSL_get_CRYPTO_free(in);
            break;
        case OSSL_FUNC_CRYPTO_CLEAR_FREE:
            c_CRYPTO_clear_free = OSSL_get_CRYPTO_clear_free(in);
            break;
        case OSSL_FUNC_CRYPTO_REALLOC:
            c_CRYPTO_realloc = OSSL_get_CRYPTO_realloc(in);
            break;
        case OSSL_FUNC_CRYPTO_CLEAR_REALLOC:
            c_CRYPTO_clear_realloc = OSSL_get_CRYPTO_clear_realloc(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_MALLOC:
            c_CRYPTO_secure_malloc = OSSL_get_CRYPTO_secure_malloc(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_ZALLOC:
            c_CRYPTO_secure_zalloc = OSSL_get_CRYPTO_secure_zalloc(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_FREE:
            c_CRYPTO_secure_free = OSSL_get_CRYPTO_secure_free(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE:
            c_CRYPTO_secure_clear_free = OSSL_get_CRYPTO_secure_clear_free(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_ALLOCATED:
            c_CRYPTO_secure_allocated = OSSL_get_CRYPTO_secure_allocated(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    /*  Create a context. */
    if ((ctx = OPENSSL_CTX_new()) == NULL)
        return 0;
    if ((fgbl = openssl_ctx_get_data(ctx, OPENSSL_CTX_FIPS_PROV_INDEX,
                                     &fips_prov_ossl_ctx_method)) == NULL) {
        OPENSSL_CTX_free(ctx);
        return 0;
    }
    fgbl->prov = provider;
    *out = fips_dispatch_table;
    *provctx = ctx;

    /*
     * TODO(3.0): Remove me. This is just a dummy call to demonstrate making
     * EVP calls from within the FIPS module.
     */
    if (!dummy_evp_call(*provctx)) {
        OPENSSL_CTX_free(*provctx);
        *provctx = NULL;
        return 0;
    }

    return 1;
}

/*
 * The internal init function used when the FIPS module uses EVP to call
 * another algorithm also in the FIPS module. This is a recursive call that has
 * been made from within the FIPS module itself. To make this work, we populate
 * the provider context of this inner instance with the same library context
 * that was used in the EVP call that initiated this recursive call.
 */
OSSL_provider_init_fn fips_intern_provider_init;
int fips_intern_provider_init(const OSSL_PROVIDER *provider,
                              const OSSL_DISPATCH *in,
                              const OSSL_DISPATCH **out,
                              void **provctx)
{
    OSSL_core_get_library_context_fn *c_get_libctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBRARY_CONTEXT:
            c_get_libctx = OSSL_get_core_get_library_context(in);
            break;
        default:
            break;
        }
    }

    if (c_get_libctx == NULL)
        return 0;

    *provctx = c_get_libctx(provider);

    /*
     * Safety measure...  we should get the library context that was
     * created up in OSSL_provider_init().
     */
    if (*provctx == NULL)
        return 0;

    *out = intern_dispatch_table;
    return 1;
}

void ERR_new(void)
{
    c_new_error(NULL);
}

void ERR_set_debug(const char *file, int line, const char *func)
{
    c_set_error_debug(NULL, file, line, func);
}

void ERR_set_error(int lib, int reason, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    c_vset_error(NULL, ERR_PACK(lib, 0, reason), fmt, args);
    va_end(args);
}

void ERR_vset_error(int lib, int reason, const char *fmt, va_list args)
{
    c_vset_error(NULL, ERR_PACK(lib, 0, reason), fmt, args);
}

const OSSL_PROVIDER *FIPS_get_provider(OPENSSL_CTX *ctx)
{
    FIPS_GLOBAL *fgbl = openssl_ctx_get_data(ctx, OPENSSL_CTX_FIPS_PROV_INDEX,
                                             &fips_prov_ossl_ctx_method);

    if (fgbl == NULL)
        return NULL;

    return fgbl->prov;
}

void *CRYPTO_malloc(size_t num, const char *file, int line)
{
    return c_CRYPTO_malloc(num, file, line);
}

void *CRYPTO_zalloc(size_t num, const char *file, int line)
{
    return c_CRYPTO_zalloc(num, file, line);
}

void CRYPTO_free(void *ptr, const char *file, int line)
{
    c_CRYPTO_free(ptr, file, line);
}

void CRYPTO_clear_free(void *ptr, size_t num, const char *file, int line)
{
    c_CRYPTO_clear_free(ptr, num, file, line);
}

void *CRYPTO_realloc(void *addr, size_t num, const char *file, int line)
{
    return c_CRYPTO_realloc(addr, num, file, line);
}

void *CRYPTO_clear_realloc(void *addr, size_t old_num, size_t num,
                           const char *file, int line)
{
    return c_CRYPTO_clear_realloc(addr, old_num, num, file, line);
}

void *CRYPTO_secure_malloc(size_t num, const char *file, int line)
{
    return c_CRYPTO_secure_malloc(num, file, line);
}

void *CRYPTO_secure_zalloc(size_t num, const char *file, int line)
{
    return c_CRYPTO_secure_zalloc(num, file, line);
}

void CRYPTO_secure_free(void *ptr, const char *file, int line)
{
    c_CRYPTO_secure_free(ptr, file, line);
}

void CRYPTO_secure_clear_free(void *ptr, size_t num, const char *file, int line)
{
    c_CRYPTO_secure_clear_free(ptr, num, file, line);
}

int CRYPTO_secure_allocated(const void *ptr)
{
    return c_CRYPTO_secure_allocated(ptr);
}
