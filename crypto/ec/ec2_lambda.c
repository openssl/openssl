/**
 * Binary curve arithmetic using lambda-projective coordinates.
 * Only supports short binary curve coeffs a=0 and a=1.
 * Essentially projective form of (x, y) -> (x, lambda)
 * where lambda = x XOR y/x.
 *
 * NB: Everything internally is lambda-affine/proj, relies
 * on set/get_affine_coordinates function pointers for the
 * "external"-facing interface to handle the conversion
 * to/from the standard short form.
 *
 * See "Faster Binary Curve Software: A Case Study",
 * NordSec 2015, to appear.
 *
 * @author Billy Brumley <billy.brumley AT tut DOT fi>
 */

#include <openssl/err.h>

#include "internal/bn_int.h"
#include "ec_lcl.h"

#ifndef OPENSSL_NO_EC2M

const EC_METHOD *EC_GF2m_lambda_method(void)
{
    static const EC_METHOD ret = {
        EC_FLAGS_DEFAULT_OCT,
        NID_X9_62_characteristic_two_field,
        ec_GF2m_simple_group_init,
        ec_GF2m_simple_group_finish,
        ec_GF2m_simple_group_clear_finish,
        ec_GF2m_simple_group_copy,
        ec_GF2m_simple_group_set_curve,
        ec_GF2m_simple_group_get_curve,
        ec_GF2m_simple_group_get_degree,
        ec_group_simple_order_bits,
        ec_GF2m_simple_group_check_discriminant,
        ec_GF2m_simple_point_init,
        ec_GF2m_simple_point_finish,
        ec_GF2m_simple_point_clear_finish,
        ec_GF2m_simple_point_copy,
        ec_GF2m_simple_point_set_to_infinity,
        0 /* set_Jprojective_coordinates_GFp */ ,
        0 /* get_Jprojective_coordinates_GFp */ ,
        ec_GF2m_lambda_point_set_affine_coordinates,
        ec_GF2m_lambda_point_get_affine_coordinates,
        0, 0, 0,
        ec_GF2m_lambda_add,
        ec_GF2m_lambda_dbl,
        ec_GF2m_lambda_invert,
        ec_GF2m_simple_is_at_infinity,
        ec_GF2m_lambda_is_on_curve,
        ec_GF2m_simple_cmp,
        ec_GF2m_lambda_make_affine,
        ec_GF2m_simple_points_make_affine,
        0 /* mul defaults to ec_wNAF_mul */ ,
        0,
        0,
        ec_GF2m_simple_field_mul,
        ec_GF2m_simple_field_sqr,
        ec_GF2m_simple_field_div,
        0 /* field_encode */ ,
        0 /* field_decode */ ,
        0 /* field_set_to_one */
    };

    return &ret;
}

/**
 * Computes a + a and stores the result in r.
 * Src: EFD "dbl-2013-olar"
 *
 * @param a input point in lambda-affine/proj
 * @param r output point in lambda-proj
 */
int ec_GF2m_lambda_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
                       BN_CTX *ctx)
{
    BIGNUM *t0, *t1, *t2, *t3;
    int ret = 0;

    if (EC_POINT_is_at_infinity(group, a))
        return EC_POINT_set_to_infinity(group, r);

    BN_CTX_start(ctx);

    t0 = BN_CTX_get(ctx);
    t1 = BN_CTX_get(ctx);
    t2 = BN_CTX_get(ctx);
    t3 = BN_CTX_get(ctx);
    if (t3 == NULL
            || !group->meth->field_sqr(group, t0, a->Y, ctx)
            || !group->meth->field_mul(group, t3, a->Z, a->Y, ctx)
            || !group->meth->field_sqr(group, t1, a->Z, ctx)
            || !group->meth->field_mul(group, t2, a->X, a->Z, ctx)
            || !BN_GF2m_add(t0, t3, t0)
            || (BN_is_one(group->a) && !BN_GF2m_add(t0, t0, t1))
            || !group->meth->field_sqr(group, r->X, t0, ctx)
            || !group->meth->field_mul(group, r->Z, t1, t0, ctx)
            || !group->meth->field_mul(group, t0, t3, t0, ctx)
            || !group->meth->field_sqr(group, t2, t2, ctx)
            || !BN_GF2m_add(t0, r->Z, t0)
            || !BN_GF2m_add(t0, t0, r->X)
            || !BN_GF2m_add(r->Y, t0, t2))
        goto done;
    ret = 1;

 done:
    r->Z_is_one = 0;
    BN_CTX_end(ctx);
    return ret;
}

/**
 * Computes a + b and stores the result in r.
 * NB: Call through the wrapper.
 * Src: EFD "add-2013-olar"
 *
 * @param a input point in lambda-affine/proj
 * @param b input point in lambda-affine
 * @param r output point in lambda-proj
 */
static int ec_GF2m_lambda_add_mixed(const EC_GROUP *group, EC_POINT *r,
                                    const EC_POINT *a, const EC_POINT *b,
                                    BN_CTX *ctx)
{
    BIGNUM *t0, *t1, *t2, *t3;
    int ret = 0;
    BN_CTX_start(ctx);

    t0 = BN_CTX_get(ctx);
    t1 = BN_CTX_get(ctx);
    t2 = BN_CTX_get(ctx);
    t3 = BN_CTX_get(ctx);
    if (t3 == NULL
            || !group->meth->field_mul(group, t1, b->Y, a->Z, ctx)
            || !BN_GF2m_add(t2, t1, a->Y)
            || !group->meth->field_mul(group, t1, b->X, a->Z, ctx)
            || !BN_GF2m_add(t0, t1, a->X))
        goto done;

    if (BN_is_zero(t0)) {
        if (BN_is_zero(t2)) {
            /* a and b are the same in lambda-affine, so double */
            ret = ec_GF2m_lambda_dbl(group, r, b, ctx);
        } else {
            /* b = -a, so infty */
            ret = EC_POINT_set_to_infinity(group, r);
        }
    } else {
        if (!group->meth->field_mul(group, t1, t1, t2, ctx)
                || !group->meth->field_mul(group, t3, a->X, t2, ctx)
                || !group->meth->field_sqr(group, t0, t0, ctx)
                || !group->meth->field_mul(group, r->X, t1, t3, ctx)
                || !BN_GF2m_add(t3, a->Z, a->Y)
                || !group->meth->field_mul(group, t2, t0, t2, ctx)
                || !BN_GF2m_add(t0, t0, t1)
                || !group->meth->field_mul(group, t3, t3, t2, ctx)
                || !group->meth->field_sqr(group, t0, t0, ctx)
                || !group->meth->field_mul(group, r->Z, a->Z, t2, ctx)
                || !BN_GF2m_add(r->Y, t3, t0))
            goto done;
        ret = 1;
    }

 done:
    BN_CTX_end(ctx);
    return ret;
}

/**
 * Computes a + b and stores the result in r.
 * NB: Call through the wrapper.
 * Src: EFD "add-2013-olar"
 *
 * @param a input point in lambda-affine/proj
 * @param b input point in lambda-affine/proj
 * @param r output point in lambda-proj
 */
static int ec_GF2m_lambda_add_proj(const EC_GROUP *group, EC_POINT *r,
                                   const EC_POINT *a, const EC_POINT *b,
                                   BN_CTX *ctx)
{
    BIGNUM *t0, *t1, *t2, *t3, *t4, *t5;
    int ret = 0;
    BN_CTX_start(ctx);

    t0 = BN_CTX_get(ctx);
    t1 = BN_CTX_get(ctx);
    t2 = BN_CTX_get(ctx);
    t3 = BN_CTX_get(ctx);
    t4 = BN_CTX_get(ctx);
    t5 = BN_CTX_get(ctx);
    if (t5 == NULL
            || !group->meth->field_mul(group, t3, a->X, b->Z, ctx)
            || !group->meth->field_mul(group, t2, b->X, a->Z, ctx)
            || !group->meth->field_mul(group, t0, b->Y, a->Z, ctx)
            || !group->meth->field_mul(group, t1, b->Z, a->Y, ctx)
            || !BN_GF2m_add(t0, t0, t1)
            || !BN_GF2m_add(t1, t2, t3))
        goto done;

    if (BN_is_zero(t1)) {
        if (BN_is_zero(t0)) {
            /* a and b are the same in lambda-affine, so double */
            ret = ec_GF2m_lambda_dbl(group, r, a, ctx);
        } else {
            /* b = -a, so infty */
            ret = EC_POINT_set_to_infinity(group, r);
        }
    } else {
        if (!BN_GF2m_add(t4, a->Z, a->Y)
                || !group->meth->field_mul(group, t2, t2, t0, ctx)
                || !group->meth->field_sqr(group, t5, t1, ctx)
                || !group->meth->field_mul(group, t3, t3, t0, ctx)
                || !group->meth->field_mul(group, t1, t5, t0, ctx)
                || !group->meth->field_mul(group, r->X, t2, t3, ctx)
                || !group->meth->field_mul(group, t0, b->Z, t1, ctx)
                || !BN_GF2m_add(t1, t5, t2)
                || !group->meth->field_mul(group, t4, t4, t0, ctx)
                || !group->meth->field_sqr(group, t1, t1, ctx)
                || !group->meth->field_mul(group, r->Z, a->Z, t0, ctx)
                || !BN_GF2m_add(r->Y, t4, t1))
            goto done;

        ret = 1;
    }

 done:
    BN_CTX_end(ctx);
    return ret;
}

/**
 * Computes a + b and stores the result in r.
 * Wrapper function that supports lambda-affine/proj/mixed.
 *
 * @param a input point in lambda-affine/proj
 * @param b input point in lambda-affine/proj
 * @param r output point in lambda-proj
 */
int ec_GF2m_lambda_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
                       const EC_POINT *b, BN_CTX *ctx)
{
    int ret = 0;

    if (EC_POINT_is_at_infinity(group, a)) {
        if (!EC_POINT_copy(r, b))
            return 0;
        return 1;
    }

    if (EC_POINT_is_at_infinity(group, b)) {
        if (!EC_POINT_copy(r, a))
            return 0;
        return 1;
    }

    if (a == b)
        ret = ec_GF2m_lambda_dbl(group, r, a, ctx);
    else if (b->Z_is_one)
        ret = ec_GF2m_lambda_add_mixed(group,r,a,b,ctx);
    else if (a->Z_is_one)
        ret = ec_GF2m_lambda_add_mixed(group,r,b,a,ctx);
    else
        ret = ec_GF2m_lambda_add_proj(group,r,a,b,ctx);

    r->Z_is_one = 0;
    return ret;
}

/**
 * Inverts point wrt lambda-affine/proj coords.
 * I.e. -(X, Y, Z) -> (X, Y XOR Z, Z)
 *
 * @param point input and output point
 */
int ec_GF2m_lambda_invert(const EC_GROUP *group, EC_POINT *point, BN_CTX *ctx)
{
    /* -infty -> infty */
    if (EC_POINT_is_at_infinity(group, point))
        return 1;

    return BN_GF2m_add(point->Y, point->Y, point->Z);
}

/**
 * Sets point to lambda-affine coord equiv of short coords (x,y)
 * I.e. (x, y) -> (x, x XOR y/x, 1)
 * @param point output point in lambda-affine
 * @param x input coord in short-affine
 * @param y input coord in short-affine
 */
int ec_GF2m_lambda_point_set_affine_coordinates(const EC_GROUP *group,
                                                EC_POINT *point,
                                                const BIGNUM *x,
                                                const BIGNUM *y, BN_CTX *ctx)
{
    int ret = 0;

    if (x == NULL || y == NULL) {
        ECerr(EC_F_EC_GF2M_LAMBDA_POINT_SET_AFFINE_COORDINATES,
              ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (!BN_copy(point->X, x))
        goto done;
    BN_set_negative(point->X, 0);
    if (!group->meth->field_div(group, point->Y, y, point->X, ctx)
            || !BN_GF2m_add(point->Y, point->Y, point->X))
        goto done;
    BN_set_negative(point->Y, 0);
    if (!BN_one(point->Z))
        goto done;
    BN_set_negative(point->Z, 0);
    point->Z_is_one = 1;
    ret = 1;

 done:
    return ret;
}

/**
 * Sets x and y to short-affine equiv of lambda-affine/proj point.
 * I.e. (X, Y, Z) -> (X/Z, Y/Z, 1) then
 * (x, y) -> (x, (x XOR y) * x)
 *
 * @param point input point in lambda-affine/proj
 * @param x output coord in short-affine. Can be NULL.
 * @param y output coord in short-affine. Can be NULL.
 */
int ec_GF2m_lambda_point_get_affine_coordinates(const EC_GROUP *group,
                                                const EC_POINT *point,
                                                BIGNUM *x, BIGNUM *y,
                                                BN_CTX *ctx)
{
    int ret = 0;
    EC_POINT *r;

    if (EC_POINT_is_at_infinity(group, point)) {
        ECerr(EC_F_EC_GF2M_LAMBDA_POINT_GET_AFFINE_COORDINATES,
              EC_R_POINT_AT_INFINITY);
        return 0;
    }

    r = EC_POINT_new(group);
    if (r == NULL
            || !EC_POINT_copy(r, point)
            || !EC_POINT_make_affine(group, r, ctx))
        goto done;
    if (x != NULL) {
        if (!BN_copy(x, r->X))
            goto done;
        BN_set_negative(x, 0);
    }
    if (y != NULL) {
        if (!BN_GF2m_add(y, r->Y, r->X)
                || !group->meth->field_mul(group, y, y, point->X, ctx))
            goto done;
        BN_set_negative(y, 0);
    }
    ret = 1;

 done:
    EC_POINT_free(r);
    return ret;
}

/**
 * Converts lambda-affine/proj point to lambda-affine.
 * I.e. (X, Y, Z) -> (X/Z, Y/Z, 1)
 *
 * @param point input/output point
 */
int ec_GF2m_lambda_make_affine(const EC_GROUP *group, EC_POINT *point,
                               BN_CTX *ctx)
{
    int ret = 0;

    /* infty -> infty */
    if (EC_POINT_is_at_infinity(group, point))
        return 1;

    if (!BN_GF2m_mod_inv_arr(point->Z, point->Z, group->poly, ctx)
            || !group->meth->field_mul(group, point->X, point->X, point->Z, ctx)
            || !group->meth->field_mul(group, point->Y, point->Y, point->Z, ctx)
            || !BN_one(point->Z))
        goto done;

    point->Z_is_one = 1;
    ret = 1;

 done:
    return ret;
}

/**
 * Check if point satisfies the lambda-projective curve equation:
 * (L**2 + L * Z + a * Z**2) * X**2 = X**4 + b * Z**4
 *
 * @param point lambda-affine/proj point to test if its on the curve
 */
int ec_GF2m_lambda_is_on_curve(const EC_GROUP *group, const EC_POINT *point,
                               BN_CTX *ctx)
{
    int ret = 0;
    BIGNUM *t1, *t2, *t3;

    /* infty always on curve */
    if (EC_POINT_is_at_infinity(group, point))
        return 1;

    BN_CTX_start(ctx);
    t1 = BN_CTX_get(ctx);
    t2 = BN_CTX_get(ctx);
    t3 = BN_CTX_get(ctx);

    if (t3 == NULL
            || !group->meth->field_sqr(group, t1, point->Y, ctx)
            || !group->meth->field_mul(group, t2, point->Y, point->Z, ctx)
            || !BN_GF2m_add(t1, t1, t2)
            || !group->meth->field_sqr(group, t2, point->Z, ctx)
            || (BN_is_one(group->a) && !BN_GF2m_add(t1, t1, t2))
            || !group->meth->field_sqr(group, t3, point->X, ctx)
            || !BN_GF2m_add(t1, t1, t3)
            || !group->meth->field_mul(group, t1, t1, t3, ctx)
            || !group->meth->field_sqr(group, t2, t2, ctx)
            || !group->meth->field_mul(group, t2, t2, group->b, ctx)
            || !BN_GF2m_add(t1, t1, t2))
        goto done;

    ret = BN_is_zero(t1);

 done:
    BN_CTX_end(ctx);
    return ret;
}

#endif
