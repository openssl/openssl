/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>
#include <openssl/err.h>
#include "prov/blake2.h"
#include "prov/digestcommon.h"
#include "prov/implementations.h"

/*
 * A descriptor for BLAKE2 functions we use.  This helps us avoid
 * too much code block copying.  For all these, C may be passed a
 * pointer to BLAKE2S_CTX or BLAKE2B_CTX, and P may be passed a
 * pointer to BLAKE2S_PARAM or BLAKE2S_PARAM, as appropriate for
 * each function.
 */
typedef int blake2sb_final_fn(unsigned char *md, void *C);
typedef void blake2sb_set_digest_length_fn(void *C, uint8_t outlen);
typedef uint8_t blake2sb_get_digest_length_fn(void *C);
struct blake2sb_desc_st {
    uint8_t max_outlen;
    blake2sb_final_fn *final;
    blake2sb_set_digest_length_fn *set_digest_length;
    blake2sb_get_digest_length_fn *get_digest_length;
};

static const struct blake2sb_desc_st blake2s256_desc = {
    BLAKE2S_DIGEST_LENGTH,
    (blake2sb_final_fn *)ossl_blake2s_final,
    (blake2sb_set_digest_length_fn *)ossl_blake2s_set_digest_length,
    (blake2sb_get_digest_length_fn *)ossl_blake2s_get_digest_length
};

static const struct blake2sb_desc_st blake2b512_desc = {
    BLAKE2B_DIGEST_LENGTH,
    (blake2sb_final_fn *)ossl_blake2b_final,
    (blake2sb_set_digest_length_fn *)ossl_blake2b_set_digest_length,
    (blake2sb_get_digest_length_fn *)ossl_blake2b_get_digest_length
};

static int blake2sb_final(const struct blake2sb_desc_st *desc, void *C,
                          unsigned char *out, size_t *outl, size_t outsz)
{
    uint8_t outlen = desc->get_digest_length(C);

    if (!ossl_prov_is_running())
        return 0;
    if (outsz < outlen)
        return 0;
    *outl = outlen;
    return desc->final(out, C);
}

static const OSSL_PARAM known_blake2sb_settable_ctx_params[] = {
    {OSSL_DIGEST_PARAM_XOFLEN, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
    OSSL_PARAM_END
};

static const OSSL_PARAM *
ossl_blake2sb_settable_ctx_params(ossl_unused void *pctx,
                                  ossl_unused void *ctx)
{
    return known_blake2sb_settable_ctx_params;
}

static int blake2sb_set_ctx_params(const struct blake2sb_desc_st *desc,
                                   void *C, const OSSL_PARAM params[])
{
    size_t xoflen;
    const OSSL_PARAM *param;

    if (C == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (params == NULL)
        return 1;

    param = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_XOFLEN);
    if (param != NULL) {
        if (!OSSL_PARAM_get_size_t(param, &xoflen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        /*
         * According to spec, the output length can't be less than 1.  However,
         * OpenSSL tests do call EVP_DigestFinalXOF() with 0 for length, and
         * EVP_DigestFinalXOF() uses that to set the xoflen unchecked, so we
         * allow it here, and ossl_blake2[sb]_final() will do the right thing.
         */
        if (/* xoflen < 1 || */ xoflen > desc->max_outlen) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH,
                           "Must be a number from 1 to %u, is %zu",
                           desc->max_outlen, xoflen);
            return 0;
        }
        desc->set_digest_length(C, (uint8_t)xoflen);
    }

    return 1;
}

static OSSL_FUNC_digest_final_fn ossl_blake2s256_final;
static OSSL_FUNC_digest_final_fn ossl_blake2b512_final;

static OSSL_FUNC_digest_settable_ctx_params_fn ossl_blake2sb_settable_ctx_params;

static OSSL_FUNC_digest_set_ctx_params_fn ossl_blake2s256_set_ctx_params;
static OSSL_FUNC_digest_set_ctx_params_fn ossl_blake2b512_set_ctx_params;

static int ossl_blake2s256_init(void *ctx)
{
    BLAKE2S_PARAM P;

    ossl_blake2s_param_init(&P);
    return ossl_blake2s_init((BLAKE2S_CTX *)ctx, &P);
}

static int ossl_blake2b512_init(void *ctx)
{
    BLAKE2B_PARAM P;

    ossl_blake2b_param_init(&P);
    return ossl_blake2b_init((BLAKE2B_CTX *)ctx, &P);
}

static int ossl_blake2s256_final(void *ctx,
                                 unsigned char *out, size_t *outl, size_t outsz)
{
    return blake2sb_final(&blake2s256_desc, ctx, out, outl, outsz);
}

static int ossl_blake2b512_final(void *ctx,
                                 unsigned char *out, size_t *outl, size_t outsz)
{
    return blake2sb_final(&blake2b512_desc, ctx, out, outl, outsz);
}

/*
 * prov/digestcommon.h's PROV_FUNC_DIGEST_FINAL makes assumptions that do not
 * fit the needs of BLAKE2 final, as it allows variable output lengths, which
 * that macro isn't adapted for.  Therefore, we make it do nothing, and hack
 * the internal names that it would produce otherwise.
 */
#undef PROV_FUNC_DIGEST_FINAL
#define PROV_FUNC_DIGEST_FINAL(name, dgstsize, fin)
#define blake2s256_internal_final ossl_blake2s256_final
#define blake2b512_internal_final ossl_blake2b512_final


static int ossl_blake2s256_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    return blake2sb_set_ctx_params(&blake2s256_desc, ctx, params);
}

static int ossl_blake2b512_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    return blake2sb_set_ctx_params(&blake2b512_desc, ctx, params);
}

/* ossl_blake2s256_functions */
IMPLEMENT_digest_functions_with_settable_ctx
(blake2s256, BLAKE2S_CTX, BLAKE2S_BLOCKBYTES, BLAKE2S_DIGEST_LENGTH, 0,
 ossl_blake2s256_init, ossl_blake2s_update, ossl_blake2s256_final,
 ossl_blake2sb_settable_ctx_params, ossl_blake2s256_set_ctx_params)

/* ossl_blake2b512_functions */
IMPLEMENT_digest_functions_with_settable_ctx
(blake2b512, BLAKE2B_CTX, BLAKE2B_BLOCKBYTES, BLAKE2B_DIGEST_LENGTH, 0,
 ossl_blake2b512_init, ossl_blake2b_update, ossl_blake2b512_final,
 ossl_blake2sb_settable_ctx_params, ossl_blake2b512_set_ctx_params)
