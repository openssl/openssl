/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/evperr.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#ifndef OPENSSL_NO_ARGON2
int EVP_KDF_argon2(uint8_t *out, size_t outlen,
    int alg_type,
    const uint8_t *pass, size_t passlen,
    const uint8_t *salt, size_t saltlen,
    uint32_t lanes, uint32_t memorycost, uint32_t iterations,
    OSSL_LIB_CTX *libctx, const OSSL_PARAM *optionals)
{
    int ret = 0;
    EVP_KDF_CTX *kctx = NULL;
    EVP_KDF *kdf = NULL;
    OSSL_PARAM params[7], *p = params;
    const OSSL_PARAM *propq_param;
    const char *propq = NULL;
    const char *alg;

    switch (alg_type) {
    case EVP_KDF_ARGON2ID_TYPE:
        alg = "argon2id";
        break;
    case EVP_KDF_ARGON2I_TYPE:
        alg = "argon2i";
        break;
    case EVP_KDF_ARGON2D_TYPE:
        alg = "argon2d";
        break;
    default:
        ERR_raise(ERR_LIB_EVP, EVP_R_BAD_ALGORITHM_NAME);
        return 0;
    }
    if (pass == NULL || passlen == 0) {
        ERR_raise_data(ERR_LIB_EVP, EVP_R_INVALID_VALUE, "Password required");
        return 0;
    }
    if (salt == NULL || saltlen == 0) {
        ERR_raise_data(ERR_LIB_EVP, EVP_R_INVALID_VALUE, "Salt required");
        return 0;
    }

    propq_param = OSSL_PARAM_locate_const(optionals, OSSL_ALG_PARAM_PROPERTIES);
    if (propq_param != NULL && !OSSL_PARAM_get_utf8_string_ptr(propq_param, &propq))
        return 0;

    kdf = EVP_KDF_fetch(libctx, alg, propq);
    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL)
        goto err;

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (uint8_t *)pass, passlen);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (uint8_t *)salt, saltlen);
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memorycost);
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iterations);
    *p = OSSL_PARAM_construct_end();

    if (optionals != NULL && !EVP_KDF_CTX_set_params(kctx, optionals)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_CANNOT_SET_PARAMETERS);
        goto err;
    }

    if (EVP_KDF_derive(kctx, out, outlen, params) != 1)
        goto err;
    ret = 1;
err:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    return ret;
}
#endif /* OPENSSL_NO_ARGON2 */
