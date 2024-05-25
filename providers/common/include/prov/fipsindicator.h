/*
 * Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifdef FIPS_MODULE

# include <openssl/core.h> /* OSSL_CALLBACK, OSSL_LIB_CTX */


typedef struct ossl_fips_indicator_st {
    int strict_checks;
    int approved;
} ossl_FIPS_INDICATOR;

typedef int (OSSL_FIPS_CHECK_CB)(OSSL_LIB_CTX *libctx);

int ossl_FIPS_INDICATOR_callback(OSSL_LIB_CTX *libctx, const char *type,
                                 const char *desc);

void ossl_FIPS_INDICATOR_init(ossl_FIPS_INDICATOR *ind);
void ossl_FIPS_INDICATOR_set_approved(ossl_FIPS_INDICATOR *ind, int approved);
int ossl_FIPS_INDICATOR_get_approved(const ossl_FIPS_INDICATOR *ind);
void ossl_FIPS_INDICATOR_set_strict(ossl_FIPS_INDICATOR *ind, int strict);
int ossl_FIPS_INDICATOR_get_strict(const ossl_FIPS_INDICATOR *ind);

/* Place this in the algorithm ctx structure */
# define OSSL_FIPS_INDICATOR_DECLARE() ossl_FIPS_INDICATOR indicator;
/* Call this to initialize the indicator to undefined values */
# define OSSL_FIPS_INDICATOR_INIT(ctx) ossl_FIPS_INDICATOR_init(&ctx->indicator);

/* This may be called once before doing the fips checks */
# define OSSL_FIPS_INDICATOR_SET_APPROVED(ctx) \
    ossl_FIPS_INDICATOR_set_approved(&ctx->indicator, 1);

/* This should be called if a fips check fails, to indicate the operation is not approved */
# define OSSL_FIPS_INDICATOR_SET_NOT_APPROVED(ctx, algname, opname, config_check_fn) \
    set_not_approved(ctx, algname, opname, config_check_fn)

/*
 * Create a static function that should be called when a FIPS algorithm check fails.
 *
 * It sets the 'approved' value to 0 which can then be retrieved via a call to
 * the algorithms get_ctx_params().
 * If 'strict_checks' is set to 1 then it returns 0,
 * otherwise it returns the result of a user defined indicator callback
 * (The callback can be used for logging unapproved operations).
 *
 * strict_checks' will be retrieved from config_check_fn(), if
 * it has not been set via the algorithms set_ctx_params().
 * The algorithm 'ctx' is assumed to contain the fields for libctx,
 * and the values defined by OSSL_FIPS_INDICATOR_DECLARE().
 */
# define OSSL_FIPS_INDICATOR_DEFINE_NOT_APPROVED(CTX_TYPE) \
static int set_not_approved(CTX_TYPE *ctx, \
                            const char *algname, const char *opname, \
                            OSSL_FIPS_CHECK_CB *config_check_fn) \
{ \
    ossl_FIPS_INDICATOR *ind = &ctx->indicator; \
    ossl_FIPS_INDICATOR_set_approved(ind, 0); \
    if (config_check_fn != NULL && ossl_FIPS_INDICATOR_get_strict(ind) == -1) \
        ossl_FIPS_INDICATOR_set_strict(ind, config_check_fn(ctx->libctx)); \
    if (ossl_FIPS_INDICATOR_get_strict(ind) == 1 \
            || !ossl_FIPS_INDICATOR_callback(ctx->libctx, algname, opname)) \
        return 0; \
    return 1; \
}

# define OSSL_FIPS_INDICATOR_SETTABLE_CTX_PARAM() \
    OSSL_PARAM_int(OSSL_ALG_PARAM_STRICT_CHECKS, NULL),

# define OSSL_FIPS_INDICATOR_SET_CTX_PARAM(ctx)  { \
    const OSSL_PARAM *p1 = OSSL_PARAM_locate_const(params, \
                                                   OSSL_ALG_PARAM_STRICT_CHECKS); \
    if (p1 != NULL) { \
        int in; \
        if (!OSSL_PARAM_get_int(p1, &in)) \
            return 0; \
        ossl_FIPS_INDICATOR_set_strict(&ctx->indicator, in); \
    } \
}

# define OSSL_FIPS_INDICATOR_GETTABLE_CTX_PARAM() \
    OSSL_PARAM_int(OSSL_ALG_PARAM_APPROVED_INDICATOR, NULL),

# define OSSL_FIPS_INDICATOR_GET_CTX_PARAM(ctx)  { \
    OSSL_PARAM *p1 = OSSL_PARAM_locate(params, OSSL_ALG_PARAM_APPROVED_INDICATOR); \
    if (p1 != NULL \
        && !OSSL_PARAM_set_int(p1, \
                               ossl_FIPS_INDICATOR_get_approved(&ctx->indicator))) \
        return 0; \
}

#else
# define OSSL_FIPS_INDICATOR_DECLARE()
# define OSSL_FIPS_INDICATOR_INIT(ctx)
# define OSSL_FIPS_INDICATOR_SET_APPROVED(ctx)
# define OSSL_FIPS_INDICATOR_SET_NOT_APPROVED(ctx, algname, opname, fn)
# define OSSL_FIPS_INDICATOR_DEFINE_NOT_APPROVED(CTX_TYPE)
# define OSSL_FIPS_INDICATOR_SETTABLE_CTX_PARAM()
# define OSSL_FIPS_INDICATOR_SET_CTX_PARAM(ctx)
# define OSSL_FIPS_INDICATOR_GETTABLE_CTX_PARAM()
# define OSSL_FIPS_INDICATOR_GET_CTX_PARAM(ctx)
#endif
