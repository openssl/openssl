/*
 * Copyright 2002-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * ECDH low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <string.h>
#include <limits.h>

#include "internal/cryptlib.h"

#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
#include "ec_local.h"
#include "crypto/bn.h" /* bn_get_ossl_fn() */
#include "crypto/fn.h" /* OSSL_FN_mod_mul() */
#include "crypto/fn_intern.h" /* ossl_fn_get_dsize() */

int ossl_ecdh_compute_key(unsigned char **psec, size_t *pseclen,
    const EC_POINT *pub_key, const EC_KEY *ecdh)
{
    if (ecdh->group->meth->ecdh_compute_key == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_CURVE_DOES_NOT_SUPPORT_ECDH);
        return 0;
    }

    return ecdh->group->meth->ecdh_compute_key(psec, pseclen, pub_key, ecdh);
}

/*-
 * ossl_ecdh_simple_compute_key() below dispatches by field type to one of two
 * implementations of the same primitive:
 *
 *  - ecdh_simple_compute_key_bignum() - the classic variable-width BIGNUM
 *    computation, used for GF(2^m) groups;
 *  - ecdh_simple_compute_key_fn() - the constant-time OSSL_FN variant for
 *    prime-field (GF(p)) groups, where neither the private key nor the shared
 *    secret is ever materialised as a variable-width BIGNUM.
 *
 * Both are based on the following primitives in the IEEE 1363 standard:
 *  - ECKAS-DH1
 *  - ECSVDP-DH
 *
 * They also conform to SP800-56A r3
 * See Section 5.7.1.2 "Elliptic Curve Cryptography Cofactor Diffie-Hellman
 * (ECC CDH) Primitive:". The steps listed below refer to SP800-56A.
 */
static int ecdh_simple_compute_key_bignum(unsigned char **pout, size_t *poutlen,
    const EC_POINT *pub_key, const EC_KEY *ecdh)
{
    BN_CTX *ctx;
    EC_POINT *tmp = NULL;
    BIGNUM *x = NULL;
    const BIGNUM *priv_key;
    const EC_GROUP *group;
    int ret = 0;
    size_t buflen, len;
    unsigned char *buf = NULL;

    if ((ctx = BN_CTX_new_ex(ecdh->libctx)) == NULL)
        goto err;
    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    if (x == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }

    priv_key = EC_KEY_get0_private_key(ecdh);
    if (priv_key == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PRIVATE_KEY);
        goto err;
    }

    group = EC_KEY_get0_group(ecdh);

    /*
     * Step(1) - Compute the point tmp = cofactor * owners_private_key
     *                                   * peer_public_key.
     */
    if (EC_KEY_get_flags(ecdh) & EC_FLAG_COFACTOR_ECDH) {
        if (!EC_GROUP_get_cofactor(group, x, NULL)) {
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto err;
        }
        if (!BN_mul(x, x, priv_key, ctx)) {
            ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
            goto err;
        }
        priv_key = x;
    }

    if ((tmp = EC_POINT_new(group)) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }

    if (!EC_POINT_mul(group, tmp, NULL, pub_key, priv_key, ctx)) {
        ERR_raise(ERR_LIB_EC, EC_R_POINT_ARITHMETIC_FAILURE);
        goto err;
    }

    /*
     * Step(2) : If point tmp is at infinity then clear intermediate values and
     * exit. Note: getting affine coordinates returns 0 if point is at infinity.
     * Step(3a) : Get x-coordinate of point x = tmp.x
     */
    if (!EC_POINT_get_affine_coordinates(group, tmp, x, NULL, ctx)) {
        ERR_raise(ERR_LIB_EC, EC_R_POINT_ARITHMETIC_FAILURE);
        goto err;
    }

    /*
     * Step(3b) : convert x to a byte string, using the field-element-to-byte
     * string conversion routine defined in Appendix C.2
     */
    buflen = (EC_GROUP_get_degree(group) + 7) / 8;
    len = BN_num_bytes(x);
    if (len > buflen) {
        ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((buf = OPENSSL_malloc(buflen)) == NULL)
        goto err;

    memset(buf, 0, buflen - len);
    if (len != (size_t)BN_bn2bin(x, buf + buflen - len)) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }

    *pout = buf;
    *poutlen = buflen;
    buf = NULL;

    ret = 1;

err:
    /* Step(4) : Destroy all intermediate calculations */
    BN_clear(x);
    EC_POINT_clear_free(tmp);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    OPENSSL_free(buf);
    return ret;
}

/*
 * Compose OSSL_FN_CTX arena sizes, honouring the _ctx_size convention that a
 * 0 means error.  ctx_add_size() returns 0 on overflow; ctx_max_size() takes
 * the larger of two sequential (non-overlapping) nested needs.
 */
static size_t ctx_add_size(size_t a, size_t b)
{
    size_t r = a + b;

    return r < a ? 0 : r;
}

static size_t ctx_max_size(size_t a, size_t b)
{
    return a > b ? a : b;
}

static int ecdh_simple_compute_key_fn(unsigned char **pout, size_t *poutlen,
    const EC_POINT *pub_key, const EC_KEY *ecdh)
{
    EC_POINT *tmp = NULL;
    const BIGNUM *priv_key;
    const OSSL_FN *scalar;
    const EC_GROUP *group;
    OSSL_FN_CTX *fnctx = NULL;
    const void *token = NULL;
    int ret = 0;
    size_t buflen;
    unsigned char *buf = NULL;

    priv_key = EC_KEY_get0_private_key(ecdh);
    if (priv_key == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PRIVATE_KEY);
        goto err;
    }
    scalar = bn_get_ossl_fn(priv_key);

    group = EC_KEY_get0_group(ecdh);

    if ((tmp = EC_POINT_new(group)) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }

    buflen = (EC_GROUP_get_degree(group) + 7) / 8;
    if ((buf = OPENSSL_malloc(buflen)) == NULL)
        goto err;

    /*
     * Step(1) - Compute the point tmp = cofactor * owners_private_key
     *                                   * peer_public_key.
     * Step(2/3) - The shared secret is tmp's x-coordinate, converted to a byte
     *             string per SEC1 Appendix C.2 and padded to the field width.
     *             A tmp at the point at infinity makes the extraction fail,
     *             as getting its affine coordinates would.
     */
    if (EC_KEY_get_flags(ecdh) & EC_FLAG_COFACTOR_ECDH) {
        /*
         * Fold the (public) cofactor into the secret scalar, staying in OSSL_FN
         * form: product = (private_key * cofactor) mod cardinality.  As
         * private_key < order and cardinality = order * cofactor, this equals
         * private_key * cofactor exactly (the reduction never fires); reducing
         * modulo the cardinality - not the order - preserves the cofactor's
         * effect.  The result has the cardinality's fixed width, so a single
         * context can hold |product|, size the modular multiply (any operand of
         * that width does), and - made large enough - drive EC_POINT_mul_fn()
         * too, rather than have it allocate its own.  |product| stays valid
         * through that call because the multiply and the ladder both nest their
         * scratch in frames above our own.
         */
        const OSSL_FN *cofactor = bn_get_ossl_fn(group->cofactor);
        const OSSL_FN *cardinality = bn_get_ossl_fn(group->cardinality);
        OSSL_FN *product;
        size_t width, own, mulsz, mfsz, size;

        if (cofactor == NULL || cardinality == NULL) {
            ERR_raise(ERR_LIB_EC, EC_R_UNKNOWN_COFACTOR);
            goto err;
        }
        width = ossl_fn_get_dsize(cardinality);
        own = OSSL_FN_CTX_size(1, 1, width);
        mulsz = OSSL_FN_mod_mul_ctx_size(cardinality, scalar, cofactor,
            cardinality);
        mfsz = EC_POINT_mul_fn_ctx_size(group, tmp, cardinality, pub_key);
        if (own == 0 || mulsz == 0 || mfsz == 0)
            goto err;
        size = ctx_add_size(own, ctx_max_size(mulsz, mfsz));
        if (size == 0)
            goto err;

        if ((fnctx = OSSL_FN_CTX_secure_new_size(ecdh->libctx, size)) == NULL
            || (token = OSSL_FN_CTX_start(fnctx)) == NULL
            || (product = OSSL_FN_CTX_get_limbs(fnctx, width)) == NULL
            || !OSSL_FN_mod_mul(product, scalar, cofactor, cardinality, fnctx))
            goto err;
        scalar = product;
    }

    if (!EC_POINT_mul_fn(group, tmp, scalar, pub_key, fnctx)
        || !EC_POINT_get_affine_coords_bytes(group, tmp, buf, NULL, buflen)) {
        ERR_raise(ERR_LIB_EC, EC_R_POINT_ARITHMETIC_FAILURE);
        goto err;
    }

    *pout = buf;
    *poutlen = buflen;
    buf = NULL;

    ret = 1;

err:
    /* Step(4) - Destroy all intermediate calculations */
    if (token != NULL)
        OSSL_FN_CTX_end(fnctx, token);
    OSSL_FN_CTX_free(fnctx);
    EC_POINT_clear_free(tmp);
    OPENSSL_free(buf);
    return ret;
}

int ossl_ecdh_simple_compute_key(unsigned char **pout, size_t *poutlen,
    const EC_POINT *pub_key, const EC_KEY *ecdh)
{
    /*
     * Prime-field (GF(p)) groups take the constant-time OSSL_FN path; GF(2^m)
     * (the only other field type) keeps the BIGNUM computation.
     */
    if (EC_KEY_get0_group(ecdh)->meth->field_type == NID_X9_62_prime_field)
        return ecdh_simple_compute_key_fn(pout, poutlen, pub_key, ecdh);
    else
        return ecdh_simple_compute_key_bignum(pout, poutlen, pub_key, ecdh);
}
