/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * RSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "crypto/rsa.h"
#include "internal/param_build_set.h"

static OSSL_OP_keymgmt_new_fn rsa_newdata;
static OSSL_OP_keymgmt_gen_init_fn rsa_gen_init;
static OSSL_OP_keymgmt_gen_set_params_fn rsa_gen_set_params;
static OSSL_OP_keymgmt_gen_settable_params_fn rsa_gen_settable_params;
static OSSL_OP_keymgmt_gen_fn rsa_gen;
static OSSL_OP_keymgmt_gen_cleanup_fn rsa_gen_cleanup;
static OSSL_OP_keymgmt_free_fn rsa_freedata;
static OSSL_OP_keymgmt_get_params_fn rsa_get_params;
static OSSL_OP_keymgmt_gettable_params_fn rsa_gettable_params;
static OSSL_OP_keymgmt_has_fn rsa_has;
static OSSL_OP_keymgmt_match_fn rsa_match;
static OSSL_OP_keymgmt_validate_fn rsa_validate;
static OSSL_OP_keymgmt_import_fn rsa_import;
static OSSL_OP_keymgmt_import_types_fn rsa_import_types;
static OSSL_OP_keymgmt_export_fn rsa_export;
static OSSL_OP_keymgmt_export_types_fn rsa_export_types;

#define RSA_DEFAULT_MD "SHA256"
#define RSA_POSSIBLE_SELECTIONS                                                \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)

DEFINE_STACK_OF(BIGNUM)
DEFINE_SPECIAL_STACK_OF_CONST(BIGNUM_const, BIGNUM)

static int key_to_params(RSA *rsa, OSSL_PARAM_BLD *bld, OSSL_PARAM params[])
{
    int ret = 0;
    const BIGNUM *rsa_d = NULL, *rsa_n = NULL, *rsa_e = NULL;
    STACK_OF(BIGNUM_const) *factors = sk_BIGNUM_const_new_null();
    STACK_OF(BIGNUM_const) *exps = sk_BIGNUM_const_new_null();
    STACK_OF(BIGNUM_const) *coeffs = sk_BIGNUM_const_new_null();

    if (rsa == NULL || factors == NULL || exps == NULL || coeffs == NULL)
        goto err;

    RSA_get0_key(rsa, &rsa_n, &rsa_e, &rsa_d);
    rsa_get0_all_params(rsa, factors, exps, coeffs);

    if (!ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_RSA_N, rsa_n)
        || !ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_RSA_E, rsa_e)
        || !ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_RSA_D, rsa_d)
        || !ossl_param_build_set_multi_key_bn(bld, params, rsa_mp_factor_names,
                                              factors)
        || !ossl_param_build_set_multi_key_bn(bld, params, rsa_mp_exp_names,
                                              exps)
        || !ossl_param_build_set_multi_key_bn(bld, params, rsa_mp_coeff_names,
                                              coeffs))
        goto err;
    ret = 1;
 err:
    sk_BIGNUM_const_free(factors);
    sk_BIGNUM_const_free(exps);
    sk_BIGNUM_const_free(coeffs);
    return ret;
}

static void *rsa_newdata(void *provctx)
{
    OPENSSL_CTX *libctx = PROV_LIBRARY_CONTEXT_OF(provctx);

    return rsa_new_with_ctx(libctx);
}

static void rsa_freedata(void *keydata)
{
    RSA_free(keydata);
}

static int rsa_has(void *keydata, int selection)
{
    RSA *rsa = keydata;
    int ok = 0;

    if (rsa != NULL) {
        if ((selection & RSA_POSSIBLE_SELECTIONS) != 0)
            ok = 1;

        if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
            ok = ok && 0;     /* This will change with PSS and OAEP */
        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
            ok = ok && (RSA_get0_e(rsa) != NULL);
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && (RSA_get0_n(rsa) != NULL);
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && (RSA_get0_d(rsa) != NULL);
    }
    return ok;
}

static int rsa_match(const void *keydata1, const void *keydata2, int selection)
{
    const RSA *rsa1 = keydata1;
    const RSA *rsa2 = keydata2;
    int ok = 1;

    /* There is always an |e| */
    ok = ok && BN_cmp(RSA_get0_e(rsa1), RSA_get0_e(rsa2)) == 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && BN_cmp(RSA_get0_n(rsa1), RSA_get0_n(rsa2)) == 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && BN_cmp(RSA_get0_d(rsa1), RSA_get0_d(rsa2)) == 0;
    return ok;
}

static int rsa_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    RSA *rsa = keydata;
    int ok = 1;

    if (rsa == NULL)
        return 0;

    /* TODO(3.0) PSS and OAEP should bring on parameters */

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ok = ok && rsa_fromdata(rsa, params);

    return ok;
}

static int rsa_export(void *keydata, int selection,
                      OSSL_CALLBACK *param_callback, void *cbarg)
{
    RSA *rsa = keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ok = 1;

    if (rsa == NULL)
        return 0;

    /* TODO(3.0) PSS and OAEP should bring on parameters */

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ok = ok && key_to_params(rsa, tmpl, NULL);

    if (!ok
        || (params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL)
        goto err;

    ok = param_callback(params, cbarg);
    OSSL_PARAM_BLD_free_params(params);
err:
    OSSL_PARAM_BLD_free(tmpl);
    return ok;
}

#ifdef FIPS_MODE
/* In fips mode there are no multi-primes. */
# define RSA_KEY_MP_TYPES()                                                    \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0),
#else
/*
 * We allow up to 10 prime factors (starting with p, q).
 * NOTE: there is only 9 OSSL_PKEY_PARAM_RSA_COEFFICIENT
 */
# define RSA_KEY_MP_TYPES()                                                    \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR3, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR4, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR5, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR6, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR7, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR8, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR9, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR10, NULL, 0),                          \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT3, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT4, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT5, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT6, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT7, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT8, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT9, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT10, NULL, 0),                        \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0),                      \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT2, NULL, 0),                      \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT3, NULL, 0),                      \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT4, NULL, 0),                      \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT5, NULL, 0),                      \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT6, NULL, 0),                      \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT7, NULL, 0),                      \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT8, NULL, 0),                      \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT9, NULL, 0),
#endif

#define RSA_KEY_TYPES()                                                        \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),                                 \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),                                 \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),                                 \
RSA_KEY_MP_TYPES()

/*
 * This provider can export everything in an RSA key, so we use the exact
 * same type description for export as for import.  Other providers might
 * choose to import full keys, but only export the public parts, and will
 * therefore have the importkey_types and importkey_types functions return
 * different arrays.
 */
static const OSSL_PARAM rsa_key_types[] = {
    RSA_KEY_TYPES()
    OSSL_PARAM_END
};
/*
 * We lied about the amount of factors, exponents and coefficients, the
 * export and import functions can really deal with an infinite amount
 * of these numbers.  However, RSA keys with too many primes are futile,
 * so we at least pretend to have some limits.
 */

static const OSSL_PARAM *rsa_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return rsa_key_types;
    return NULL;
}

static const OSSL_PARAM *rsa_import_types(int selection)
{
    return rsa_imexport_types(selection);
}

static const OSSL_PARAM *rsa_export_types(int selection)
{
    return rsa_imexport_types(selection);
}

static int rsa_get_params(void *key, OSSL_PARAM params[])
{
    RSA *rsa = key;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, RSA_bits(rsa)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, RSA_security_bits(rsa)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, RSA_size(rsa)))
        return 0;

# if 0  /* TODO(3.0): PSS support pending */
    if ((p = OSSL_PARAM_locate(params,
                               OSSL_PKEY_PARAM_MANDATORY_DIGEST)) != NULL
        && RSA_get0_pss_params(rsa) != NULL) {
        const EVP_MD *md, *mgf1md;
        int min_saltlen;

        if (!rsa_pss_get_param(RSA_get0_pss_params(rsa),
                               &md, &mgf1md, &min_saltlen)) {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (!OSSL_PARAM_set_utf8_string(p, EVP_MD_name(md)))
            return 0;
    }
#endif
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) != NULL
/* TODO(3.0): PSS support pending */
#if 0
            && RSA_get0_pss_params(rsa) == NULL
#endif
            ) {
        if (!OSSL_PARAM_set_utf8_string(p, RSA_DEFAULT_MD))
            return 0;
    }
    return key_to_params(rsa, NULL, params);
}

static const OSSL_PARAM rsa_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
    RSA_KEY_TYPES()
    OSSL_PARAM_END
};

static const OSSL_PARAM *rsa_gettable_params(void)
{
    return rsa_params;
}

static int rsa_validate(void *keydata, int selection)
{
    RSA *rsa = keydata;
    int ok = 0;

    if ((selection & RSA_POSSIBLE_SELECTIONS) != 0)
        ok = 1;

    /* If the whole key is selected, we do a pairwise validation */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
        == OSSL_KEYMGMT_SELECT_KEYPAIR) {
        ok = ok && rsa_validate_pairwise(rsa);
    } else {
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && rsa_validate_private(rsa);
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && rsa_validate_public(rsa);
    }
    return ok;
}

struct rsa_gen_ctx {
    OPENSSL_CTX *libctx;

    size_t nbits;
    BIGNUM *pub_exp;
    size_t primes;

    /* For generation callback */
    OSSL_CALLBACK *cb;
    void *cbarg;
};

static int rsa_gencb(int p, int n, BN_GENCB *cb)
{
    struct rsa_gen_ctx *gctx = BN_GENCB_get_arg(cb);
    OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END };

    params[0] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL, &p);
    params[1] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION, &n);

    return gctx->cb(params, gctx->cbarg);
}

static void *rsa_gen_init(void *provctx, int selection)
{
    OPENSSL_CTX *libctx = PROV_LIBRARY_CONTEXT_OF(provctx);
    struct rsa_gen_ctx *gctx = NULL;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->libctx = libctx;
        if ((gctx->pub_exp = BN_new()) == NULL
            || !BN_set_word(gctx->pub_exp, RSA_F4)) {
            BN_free(gctx->pub_exp);
            gctx = NULL;
        } else {
            gctx->nbits = 2048;
            gctx->primes = RSA_DEFAULT_PRIME_NUM;
        }
    }
    return gctx;
}

static int rsa_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct rsa_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS)) != NULL
        && !OSSL_PARAM_get_size_t(p, &gctx->nbits))
        return 0;
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PRIMES)) != NULL
        && !OSSL_PARAM_get_size_t(p, &gctx->primes))
        return 0;
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E)) != NULL
        && !OSSL_PARAM_get_BN(p, &gctx->pub_exp))
        return 0;
    return 1;
}

static const OSSL_PARAM *rsa_gen_settable_params(void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };

    return settable;
}

static void *rsa_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct rsa_gen_ctx *gctx = genctx;
    RSA *rsa = NULL;
    BN_GENCB *gencb = NULL;

    if (gctx == NULL
        || (rsa = rsa_new_with_ctx(gctx->libctx)) == NULL)
        return NULL;

    gctx->cb = osslcb;
    gctx->cbarg = cbarg;
    gencb = BN_GENCB_new();
    if (gencb != NULL)
        BN_GENCB_set(gencb, rsa_gencb, genctx);

    if (!RSA_generate_multi_prime_key(rsa, (int)gctx->nbits, (int)gctx->primes,
                                      gctx->pub_exp, gencb)) {
        RSA_free(rsa);
        rsa = NULL;
    }

    BN_GENCB_free(gencb);

    return rsa;
}

static void rsa_gen_cleanup(void *genctx)
{
    struct rsa_gen_ctx *gctx = genctx;

    if (gctx == NULL)
        return;

    BN_clear_free(gctx->pub_exp);
    OPENSSL_free(gctx);
}

const OSSL_DISPATCH rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))rsa_newdata },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))rsa_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
      (void (*)(void))rsa_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))rsa_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))rsa_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))rsa_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))rsa_freedata },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))rsa_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))rsa_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))rsa_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))rsa_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))rsa_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))rsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))rsa_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))rsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))rsa_export_types },
    { 0, NULL }
};
