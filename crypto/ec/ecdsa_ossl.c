/*
 * Copyright 2002-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * ECDSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <string.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include "crypto/bn.h"
#include "crypto/fxn.h"
#include "crypto/fxn_intern.h" /* ossl_fxn_gen_dsa_nonce() */
#include "internal/constant_time.h"
#include "ec_local.h"
#include "internal/deterministic_nonce.h"

#define MIN_ECDSA_SIGN_ORDERBITS 64
/*
 * It is highly unlikely that a retry will happen,
 * Multiple retries would indicate that something is wrong
 * with the group parameters (which would normally only happen
 * with a bad custom group).
 */
#define MAX_ECDSA_SIGN_RETRIES 8

static int ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in,
    BIGNUM **kinvp, BIGNUM **rp,
    const unsigned char *dgst, int dlen,
    unsigned int nonce_type, const char *digestname,
    OSSL_LIB_CTX *libctx, const char *propq);
static int ecdsa_sign_setup_fxn(EC_KEY *eckey, BN_CTX *ctx_in,
    BIGNUM **kinvp, BIGNUM **rp,
    const unsigned char *dgst, int dlen,
    unsigned int nonce_type, const char *digestname,
    OSSL_LIB_CTX *libctx, const char *propq);
static int ecdsa_sign_setup_bignum(EC_KEY *eckey, BN_CTX *ctx_in,
    BIGNUM **kinvp, BIGNUM **rp,
    const unsigned char *dgst, int dlen,
    unsigned int nonce_type, const char *digestname,
    OSSL_LIB_CTX *libctx, const char *propq);

int ossl_ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
    BIGNUM **rp)
{
    if (eckey->group->meth->ecdsa_sign_setup == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_CURVE_DOES_NOT_SUPPORT_ECDSA);
        return 0;
    }

    return eckey->group->meth->ecdsa_sign_setup(eckey, ctx_in, kinvp, rp);
}

ECDSA_SIG *ossl_ecdsa_sign_sig(const unsigned char *dgst, int dgst_len,
    const BIGNUM *in_kinv, const BIGNUM *in_r,
    EC_KEY *eckey)
{
    if (eckey->group->meth->ecdsa_sign_sig == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_CURVE_DOES_NOT_SUPPORT_ECDSA);
        return NULL;
    }

    return eckey->group->meth->ecdsa_sign_sig(dgst, dgst_len,
        in_kinv, in_r, eckey);
}

int ossl_ecdsa_verify_sig(const unsigned char *dgst, int dgst_len,
    const ECDSA_SIG *sig, EC_KEY *eckey)
{
    if (eckey->group->meth->ecdsa_verify_sig == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_CURVE_DOES_NOT_SUPPORT_ECDSA);
        return 0;
    }

    return eckey->group->meth->ecdsa_verify_sig(dgst, dgst_len, sig, eckey);
}

int ossl_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
    unsigned char *sig, unsigned int *siglen,
    const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
{
    ECDSA_SIG *s;

    if (sig == NULL && (kinv == NULL || r == NULL)) {
        *siglen = ECDSA_size(eckey);
        return 1;
    }

    s = ECDSA_do_sign_ex(dgst, dlen, kinv, r, eckey);
    if (s == NULL) {
        *siglen = 0;
        return 0;
    }
    *siglen = i2d_ECDSA_SIG(s, sig != NULL ? &sig : NULL);
    ECDSA_SIG_free(s);
    return 1;
}

int ossl_ecdsa_deterministic_sign(const unsigned char *dgst, int dlen,
    unsigned char *sig, unsigned int *siglen,
    EC_KEY *eckey, unsigned int nonce_type,
    const char *digestname,
    OSSL_LIB_CTX *libctx, const char *propq)
{
    ECDSA_SIG *s;
    BIGNUM *kinv = NULL, *r = NULL;
    int ret = 0;

    if (sig == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (digestname == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_DIGEST);
        return 0;
    }

    *siglen = 0;
    if (!ecdsa_sign_setup(eckey, NULL, &kinv, &r, dgst, dlen,
            nonce_type, digestname, libctx, propq))
        return 0;

    s = ECDSA_do_sign_ex(dgst, dlen, kinv, r, eckey);
    if (s == NULL)
        goto end;

    *siglen = i2d_ECDSA_SIG(s, &sig);
    ECDSA_SIG_free(s);
    ret = 1;
end:
    BN_clear_free(kinv);
    BN_clear_free(r);
    return ret;
}

static int ecdsa_sign_setup_bignum(EC_KEY *eckey, BN_CTX *ctx_in,
    BIGNUM **kinvp, BIGNUM **rp,
    const unsigned char *dgst, int dlen,
    unsigned int nonce_type, const char *digestname,
    OSSL_LIB_CTX *libctx, const char *propq)
{
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL, *r = NULL, *X = NULL;
    const BIGNUM *order;
    EC_POINT *tmp_point = NULL;
    const EC_GROUP *group;
    int ret = 0;
    int order_bits;
    const BIGNUM *priv_key;

    if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if ((priv_key = EC_KEY_get0_private_key(eckey)) == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PRIVATE_KEY);
        return 0;
    }

    if (!EC_KEY_can_sign(eckey)) {
        ERR_raise(ERR_LIB_EC, EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING);
        return 0;
    }

    if ((ctx = ctx_in) == NULL) {
        if ((ctx = BN_CTX_new_ex(eckey->libctx)) == NULL) {
            ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
            return 0;
        }
    }

    k = BN_secure_new(); /* this value is later returned in *kinvp */
    r = BN_new(); /* this value is later returned in *rp */
    X = BN_new();
    if (k == NULL || r == NULL || X == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }
    if ((tmp_point = EC_POINT_new(group)) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }

    if ((order = EC_GROUP_get0_order(group)) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }

    /* Preallocate space */
    order_bits = BN_num_bits(order);
    /* Check the number of bits here so that an infinite loop is not possible */
    if (order_bits < MIN_ECDSA_SIGN_ORDERBITS
        || !BN_set_bit(k, order_bits)
        || !BN_set_bit(r, order_bits)
        || !BN_set_bit(X, order_bits))
        goto err;

    do {
        /* get random or deterministic value of k */
        do {
            int res = 0;

            if (dgst != NULL) {
                if (nonce_type == 1) {
                    res = ossl_gen_deterministic_nonce_rfc6979(k, order,
                        priv_key,
                        dgst, dlen,
                        digestname,
                        libctx, propq);
                } else {
                    res = ossl_bn_gen_dsa_nonce_fixed_top(k, order, priv_key,
                        dgst, dlen, ctx);
                }
            } else {
                res = ossl_bn_priv_rand_range_fixed_top(k, order, 0, ctx);
            }
            if (!res) {
                ERR_raise(ERR_LIB_EC, EC_R_RANDOM_NUMBER_GENERATION_FAILED);
                goto err;
            }
        } while (ossl_bn_is_word_fixed_top(k, 0));

        /* compute r the x-coordinate of generator * k */
        if (!EC_POINT_mul(group, tmp_point, k, NULL, NULL, ctx)) {
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto err;
        }

        if (!EC_POINT_get_affine_coordinates(group, tmp_point, X, NULL, ctx)) {
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto err;
        }

        if (!BN_nnmod(r, X, order, ctx)) {
            ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
            goto err;
        }
    } while (BN_is_zero(r));

    /* compute the inverse of k */
    if (!ossl_ec_group_do_inverse_ord(group, k, k, ctx)) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }

    /* clear old values if necessary */
    BN_clear_free(*rp);
    BN_clear_free(*kinvp);
    /* save the pre-computed values  */
    *rp = r;
    *kinvp = k;
    ret = 1;
err:
    if (!ret) {
        BN_clear_free(k);
        BN_clear_free(r);
    }
    if (ctx != ctx_in)
        BN_CTX_free(ctx);
    EC_POINT_free(tmp_point);
    BN_clear_free(X);
    return ret;
}

static int ecdsa_sign_setup_fxn(EC_KEY *eckey, BN_CTX *ctx_in,
    BIGNUM **kinvp, BIGNUM **rp,
    const unsigned char *dgst, int dlen,
    unsigned int nonce_type, const char *digestname,
    OSSL_LIB_CTX *libctx, const char *propq)
{
    BN_CTX *ctx = NULL;
    BIGNUM *r = NULL, *X = NULL, *kinv = NULL;
    const BIGNUM *order;
    EC_POINT *tmp_point = NULL;
    const EC_GROUP *group;
    int ret = 0;
    int order_bits, nlimbs;
    const BIGNUM *priv_key;
    OSSL_FXN_CTX *fxnctx = NULL;
    const void *token = NULL;
    const OSSL_FXN *order_fxn, *priv_fxn = NULL;
    OSSL_FXN *kf = NULL, *kinvf = NULL;
    size_t w, need = 0;

    if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if ((priv_key = EC_KEY_get0_private_key(eckey)) == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PRIVATE_KEY);
        return 0;
    }

    if (!EC_KEY_can_sign(eckey)) {
        ERR_raise(ERR_LIB_EC, EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING);
        return 0;
    }

    if ((ctx = ctx_in) == NULL) {
        if ((ctx = BN_CTX_new_ex(eckey->libctx)) == NULL) {
            ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
            return 0;
        }
    }

    r = BN_new(); /* this value is later returned in *rp */
    X = BN_new();
    kinv = BN_secure_new(); /* this value is later returned in *kinvp */
    if (r == NULL || X == NULL || kinv == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }
    if ((tmp_point = EC_POINT_new(group)) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }

    if ((order = EC_GROUP_get0_order(group)) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }

    order_bits = BN_num_bits(order);
    /* Check the number of bits here so that an infinite loop is not possible */
    if (order_bits < MIN_ECDSA_SIGN_ORDERBITS)
        goto err;

    /*
     * The order is public; the secret-scalar work below needs only its
     * read-only OSSL_FXN view.
     */
    nlimbs = bn_get_top(order);
    if ((order_fxn = bn_get_ossl_fxn(order)) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_OSSL_FXN_LIB);
        goto err;
    }

    /*
     * The deterministic (RFC6979) and hedged nonce generators derive k from the
     * private key; they take its read-only OSSL_FXN view and write straight
     * into the OSSL_FXN nonce, so no BIGNUM nonce is ever materialised.  The
     * random path (dgst == NULL) draws straight into the OSSL_FXN too.
     */
    if (dgst != NULL && (priv_fxn = bn_get_ossl_fxn(priv_key)) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_OSSL_FXN_LIB);
        goto err;
    }

    /*
     * Secure arena holding the secret nonce k, plus the scratch that nests on
     * top of it: the k*G ladder and the inverse below.  order_fxn is at least
     * nlimbs wide, so sizing both against it is an upper bound.  Creating the
     * arena with eckey->libctx (rather than letting EC_POINT_mul_fxn() allocate
     * its own against the possibly-NULL group->libctx) is what lets the
     * ladder's coordinate blinding draw entropy from the caller's context.
     */
    w = ossl_fxn_get_dsize(order_fxn);
    need = ossl_fxn_ctx_max_size(
        OSSL_FXN_mod_inverse_prime_ctx_size_from_sizes(w, w, w, w),
        EC_POINT_mul_fxn_ctx_size(group, tmp_point, order_fxn, NULL));
    /* ... plus the outer frame holding the nonce k itself. */
    need = ossl_fxn_ctx_add_size(need, OSSL_FXN_CTX_size(1, 1, (size_t)nlimbs));
    if (need == 0) {
        ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    fxnctx = OSSL_FXN_CTX_secure_new_size(eckey->libctx, need);
    if (fxnctx == NULL || (token = OSSL_FXN_CTX_start(fxnctx)) == NULL)
        goto err;
    if ((kf = OSSL_FXN_CTX_get_limbs(fxnctx, token, nlimbs)) == NULL)
        goto err;

    do {
        /* get random or deterministic value of k */
        do {
            if (dgst != NULL) {
                int res;

                if (nonce_type == 1)
                    res = ossl_fxn_gen_deterministic_nonce_rfc6979(kf, order,
                        priv_fxn, dgst, dlen, digestname, libctx, propq);
                else
                    res = ossl_fxn_gen_dsa_nonce(kf, order_fxn, priv_fxn,
                        dgst, dlen, eckey->libctx);
                if (!res) {
                    ERR_raise(ERR_LIB_EC,
                        EC_R_RANDOM_NUMBER_GENERATION_FAILED);
                    goto err;
                }
            } else if (!OSSL_FXN_priv_rand_range(kf, order_fxn, 0,
                           eckey->libctx)) {
                ERR_raise(ERR_LIB_EC, EC_R_RANDOM_NUMBER_GENERATION_FAILED);
                goto err;
            }
        } while (OSSL_FXN_is_zero(kf));

        /*
         * Compute r, the x-coordinate of k*G reduced mod the order.  k is the
         * secret nonce, so the multiplication goes through EC_POINT_mul_fxn();
         * the x-coordinate, and hence r, is public.
         */
        if (!EC_POINT_mul_fxn(group, tmp_point, kf, NULL, fxnctx)
            || !EC_POINT_get_affine_coordinates(group, tmp_point, X, NULL,
                ctx)) {
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto err;
        }

        if (!BN_nnmod(r, X, order, ctx)) {
            ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
            goto err;
        }
    } while (BN_is_zero(r));

    /*
     * Compute the inverse of k straight into the OSSL_FXN of the returned
     * BIGNUM, so the secret nonce is never handed over as a BIGNUM.
     */
    if ((kinvf = bn_acquire_ossl_fxn(kinv, nlimbs)) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_OSSL_FXN_LIB);
        goto err;
    }
    if (!ossl_ec_group_do_inverse_ord_fxn(group, kinvf, kf, fxnctx)) {
        bn_release(kinv, nlimbs);
        kinvf = NULL;
        ERR_raise(ERR_LIB_EC, ERR_R_OSSL_FXN_LIB);
        goto err;
    }
    bn_release(kinv, nlimbs);
    kinvf = NULL;

    /* clear old values if necessary */
    BN_clear_free(*rp);
    BN_clear_free(*kinvp);
    /* save the pre-computed values  */
    *rp = r;
    *kinvp = kinv;
    ret = 1;
err:
    if (!ret) {
        BN_clear_free(kinv);
        BN_clear_free(r);
    }
    if (token != NULL)
        OSSL_FXN_CTX_end(fxnctx, token);
    OSSL_FXN_CTX_free(fxnctx);
    if (ctx != ctx_in)
        BN_CTX_free(ctx);
    EC_POINT_free(tmp_point);
    BN_clear_free(X);
    return ret;
}

static int ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in,
    BIGNUM **kinvp, BIGNUM **rp,
    const unsigned char *dgst, int dlen,
    unsigned int nonce_type, const char *digestname,
    OSSL_LIB_CTX *libctx, const char *propq)
{
    const EC_GROUP *group;

    /*
     * Prime-field (GF(p)) groups take the constant-time OSSL_FXN secret-scalar
     * path; GF(2^m) has no EC_POINT_mul_fxn() and keeps the BIGNUM computation.
     * A NULL eckey/group is left to the BIGNUM path, which reports it.
     */
    if (eckey != NULL
        && (group = EC_KEY_get0_group(eckey)) != NULL
        && group->meth->field_type == NID_X9_62_prime_field)
        return ecdsa_sign_setup_fxn(eckey, ctx_in, kinvp, rp, dgst, dlen,
            nonce_type, digestname, libctx, propq);

    return ecdsa_sign_setup_bignum(eckey, ctx_in, kinvp, rp, dgst, dlen,
        nonce_type, digestname, libctx, propq);
}

int ossl_ecdsa_simple_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
    BIGNUM **rp)
{
    return ecdsa_sign_setup(eckey, ctx_in, kinvp, rp, NULL, 0,
        0, NULL, NULL, NULL);
}

ECDSA_SIG *ossl_ecdsa_simple_sign_sig(const unsigned char *dgst, int dgst_len,
    const BIGNUM *in_kinv, const BIGNUM *in_r,
    EC_KEY *eckey)
{
    int ok = 0, i, nlimbs;
    int retries = 0;
    BIGNUM *kinv = NULL, *m = NULL;
    const BIGNUM *order, *ckinv;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group;
    ECDSA_SIG *ret;
    const BIGNUM *priv_key;
    OSSL_FXN_CTX *fxnctx = NULL;
    const void *token = NULL;
    OSSL_FXN_MONT_CTX *mont;
    const OSSL_FXN *order_fxn;
    OSSL_FXN *t = NULL, *u = NULL, *d = NULL, *sf = NULL;
    size_t need, w;

    group = EC_KEY_get0_group(eckey);
    priv_key = EC_KEY_get0_private_key(eckey);

    if (group == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    if (priv_key == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PRIVATE_KEY);
        return NULL;
    }

    if (!EC_KEY_can_sign(eckey)) {
        ERR_raise(ERR_LIB_EC, EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING);
        return NULL;
    }

    ret = ECDSA_SIG_new();
    if (ret == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_ECDSA_LIB);
        return NULL;
    }
    ret->r = BN_new();
    ret->s = BN_new();
    if (ret->r == NULL || ret->s == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }

    if ((ctx = BN_CTX_new_ex(eckey->libctx)) == NULL
        || (m = BN_new()) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }

    if ((order = EC_GROUP_get0_order(group)) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }

    i = BN_num_bits(order);
    /*
     * Need to truncate digest if it is too long: first truncate whole bytes.
     */
    if (8 * dgst_len > i)
        dgst_len = (i + 7) / 8;
    if (!BN_bin2bn(dgst, dgst_len, m)) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }
    /* If still too long, truncate remaining bits with a shift */
    if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7))) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }

    /*
     * s = kinv * (r * d + m) mod order.  The private key d and the nonce
     * inverse kinv are secret, so the arithmetic is done with Montgomery
     * multiplications, never division, in a secure OSSL_FXN arena; r, m and
     * the resulting s are public.  Multiplying an operand in the Montgomery
     * domain by a plain one gives a plain product, so only one operand of each
     * multiplication needs converting.  Every operand is first reduced to
     * the width of the order's Montgomery modulus, which is what the
     * strict-width functions need.
     */
    nlimbs = bn_get_top(order);
    if (group->fxn_mont_ctx_ord == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_GROUP_ORDER);
        goto err;
    }
    mont = group->fxn_mont_ctx_ord;
    order_fxn = OSSL_FXN_MONT_CTX_get0_modulus(mont);
    w = ossl_fxn_get_dsize(order_fxn);
    need = ossl_fxn_ctx_max_size(ossl_ec_group_fxn_reduce_ord_ctx_size(group),
        OSSL_FXN_to_mont_quick_ctx_size_from_sizes(w, w, w));
    need = ossl_fxn_ctx_max_size(need,
        OSSL_FXN_mul_mont_quick_ctx_size_from_sizes(w, w, w, w));
    need = ossl_fxn_ctx_add_size(need, OSSL_FXN_CTX_size(1, 3, 3 * w));
    if (need == 0) {
        ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((fxnctx = OSSL_FXN_CTX_secure_new_size(eckey->libctx, need)) == NULL
        || (token = OSSL_FXN_CTX_start(fxnctx)) == NULL
        || (t = OSSL_FXN_CTX_get_limbs(fxnctx, token, w)) == NULL
        || (u = OSSL_FXN_CTX_get_limbs(fxnctx, token, w)) == NULL
        || (d = OSSL_FXN_CTX_get_limbs(fxnctx, token, w)) == NULL
        || !ossl_ec_group_fxn_reduce_ord(group, d, priv_key, fxnctx)) {
        ERR_raise(ERR_LIB_EC, ERR_R_OSSL_FXN_LIB);
        goto err;
    }

    do {
        if (in_kinv == NULL || in_r == NULL) {
            if (!ecdsa_sign_setup(eckey, ctx, &kinv, &ret->r, dgst, dgst_len,
                    0, NULL, NULL, NULL)) {
                ERR_raise(ERR_LIB_EC, ERR_R_ECDSA_LIB);
                goto err;
            }
            ckinv = kinv;
        } else {
            ckinv = in_kinv;
            if (BN_copy(ret->r, in_r) == NULL) {
                ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
                goto err;
            }
        }

        /* t = r * d, u = m, t = (t + u) * kinv */
        if (!ossl_ec_group_fxn_reduce_ord(group, u, ret->r, fxnctx)
            || !OSSL_FXN_to_mont_quick(u, u, mont, fxnctx)
            || !OSSL_FXN_mul_mont_quick(t, u, d, mont, fxnctx)
            || !ossl_ec_group_fxn_reduce_ord(group, u, m, fxnctx)
            || !OSSL_FXN_mod_add_quick(t, t, u, order_fxn)
            || !OSSL_FXN_to_mont_quick(t, t, mont, fxnctx)
            || !ossl_ec_group_fxn_reduce_ord(group, u, ckinv, fxnctx)
            || !OSSL_FXN_mul_mont_quick(t, t, u, mont, fxnctx)) {
            ERR_raise(ERR_LIB_EC, ERR_R_OSSL_FXN_LIB);
            goto err;
        }

        /* s is public: it is half of the signature */
        CONSTTIME_DECLASSIFY(ossl_fxn_get_words(t), w * OSSL_FXN_BYTES);
        if (OSSL_FXN_is_zero(t)) {
            /*
             * if kinv and r have been supplied by the caller, don't
             * generate new kinv and r values
             */
            if (in_kinv != NULL && in_r != NULL) {
                ERR_raise(ERR_LIB_EC, EC_R_NEED_NEW_SETUP_VALUES);
                goto err;
            }
            /* Avoid infinite loops cause by invalid group parameters */
            if (retries++ > MAX_ECDSA_SIGN_RETRIES) {
                ERR_raise(ERR_LIB_EC, EC_R_TOO_MANY_RETRIES);
                goto err;
            }
        } else {
            /* s != 0 => we have a valid signature */
            break;
        }
    } while (1);

    /* Move the public result s into the returned BIGNUM. */
    if ((sf = bn_acquire_ossl_fxn(ret->s, nlimbs)) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_OSSL_FXN_LIB);
        goto err;
    }
    if (OSSL_FXN_copy_truncate(sf, t) == NULL) {
        bn_release(ret->s, nlimbs);
        ERR_raise(ERR_LIB_EC, ERR_R_OSSL_FXN_LIB);
        goto err;
    }
    bn_release(ret->s, nlimbs);

    ok = 1;
err:
    if (!ok) {
        ECDSA_SIG_free(ret);
        ret = NULL;
    }
    if (token != NULL)
        OSSL_FXN_CTX_end(fxnctx, token);
    OSSL_FXN_CTX_free(fxnctx);
    BN_CTX_free(ctx);
    BN_clear_free(m);
    BN_clear_free(kinv);
    return ret;
}

/*-
 * returns
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int ossl_ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
    const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
    ECDSA_SIG *s;
    const unsigned char *p = sigbuf;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = ECDSA_SIG_new();
    if (s == NULL)
        return ret;
    if (d2i_ECDSA_SIG(&s, &p, sig_len) == NULL)
        goto err;
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_ECDSA_SIG(s, &der);
    if (derlen != sig_len || memcmp(sigbuf, der, derlen) != 0)
        goto err;
    ret = ECDSA_do_verify(dgst, dgst_len, s, eckey);
err:
    OPENSSL_free(der);
    ECDSA_SIG_free(s);
    return ret;
}

int ossl_ecdsa_simple_verify_sig(const unsigned char *dgst, int dgst_len,
    const ECDSA_SIG *sig, EC_KEY *eckey)
{
    int ret = -1, i;
    BN_CTX *ctx;
    const BIGNUM *order;
    BIGNUM *u1, *u2, *m, *X;
    EC_POINT *point = NULL;
    const EC_GROUP *group;
    const EC_POINT *pub_key;

    /* check input values */
    if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL || (pub_key = EC_KEY_get0_public_key(eckey)) == NULL || sig == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PARAMETERS);
        return -1;
    }

    if (!EC_KEY_can_sign(eckey)) {
        ERR_raise(ERR_LIB_EC, EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING);
        return -1;
    }

    ctx = BN_CTX_new_ex(eckey->libctx);
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        return -1;
    }
    BN_CTX_start(ctx);
    u1 = BN_CTX_get(ctx);
    u2 = BN_CTX_get(ctx);
    m = BN_CTX_get(ctx);
    X = BN_CTX_get(ctx);
    if (X == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }

    order = EC_GROUP_get0_order(group);
    if (order == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }

    if (BN_is_zero(sig->r) || BN_is_negative(sig->r) || BN_ucmp(sig->r, order) >= 0 || BN_is_zero(sig->s) || BN_is_negative(sig->s) || BN_ucmp(sig->s, order) >= 0) {
        ERR_raise(ERR_LIB_EC, EC_R_BAD_SIGNATURE);
        ret = 0; /* signature is invalid */
        goto err;
    }
    /* calculate tmp1 = inv(S) mod order */
    if (!ossl_ec_group_do_inverse_ord(group, u2, sig->s, ctx)) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }
    /* digest -> m */
    i = BN_num_bits(order);
    /*
     * Need to truncate digest if it is too long: first truncate whole bytes.
     */
    if (8 * dgst_len > i)
        dgst_len = (i + 7) / 8;
    if (!BN_bin2bn(dgst, dgst_len, m)) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }
    /* If still too long truncate remaining bits with a shift */
    if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7))) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }
    /* u1 = m * tmp mod order */
    if (!BN_mod_mul(u1, m, u2, order, ctx)) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }
    /* u2 = r * w mod q */
    if (!BN_mod_mul(u2, sig->r, u2, order, ctx)) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }

    if ((point = EC_POINT_new(group)) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }
    if (!EC_POINT_mul(group, point, u1, pub_key, u2, ctx)) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }

    if (!EC_POINT_get_affine_coordinates(group, point, X, NULL, ctx)) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }

    if (!BN_nnmod(u1, X, order, ctx)) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }
    /*  if the signature is correct u1 is equal to sig->r */
    ret = (BN_ucmp(u1, sig->r) == 0);
err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_POINT_free(point);
    return ret;
}
