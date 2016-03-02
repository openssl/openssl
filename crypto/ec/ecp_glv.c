#include <openssl/err.h>
#include "ec_lcl.h"

/**
 * Copyright OpenSSL 2016
 * Contents licensed under the terms of the OpenSSL license
 * See http://www.openssl.org/source/license.html for details
 *
 * Faster scalar multiplication for GLV curves:
 * http://eprint.iacr.org/2015/036
 *
 * @author Billy Brumley <billy.brumley AT tut DOT fi>
 */

/* GLV-related per-curve constants */
static const unsigned char glv_constants_secp160k1[] = {
    /* beta */
    0x9b, 0xa4, 0x8c, 0xba, 0x5e, 0xbc, 0xb9, 0xb6,
    0xbd, 0x33, 0xb9, 0x28, 0x30, 0xb2, 0xa2, 0xe0,
    0xe1, 0x92, 0xf1, 0x0a,
    /* a1 */
    0x91, 0x62, 0xfb, 0xe7, 0x39, 0x84, 0x47, 0x2a,
    0x0a, 0x9e,
    /* b1 */
    0x96, 0x34, 0x1f, 0x11, 0x38, 0x93, 0x3b, 0xc2,
    0xf5, 0x05,
    /* a2 */
    0x01, 0x27, 0x97, 0x1a, 0xf8, 0x72, 0x17, 0x82,
    0xec, 0xff, 0xa3,
    /* b2 */
    0x91, 0x62, 0xfb, 0xe7, 0x39, 0x84, 0x47, 0x2a,
    0x0a, 0x9e
};

static const unsigned char glv_constants_secp192k1[] = {
    /* beta */
    0xbb, 0x85, 0x69, 0x19, 0x39, 0xb8, 0x69, 0xc1,
    0xd0, 0x87, 0xf6, 0x01, 0x55, 0x4b, 0x96, 0xb8,
    0x0c, 0xb4, 0xf5, 0x5b, 0x35, 0xf4, 0x33, 0xc2,
    /* a1 */
    0x71, 0x16, 0x9b, 0xe7, 0x33, 0x0b, 0x30, 0x38,
    0xed, 0xb0, 0x25, 0xf1,
    /* b1 */
    0xb3, 0xfb, 0x34, 0x00, 0xde, 0xc5, 0xc4, 0xad,
    0xce, 0xb8, 0x65, 0x5c,
    /* a2 */
    0x01, 0x25, 0x11, 0xcf, 0xe8, 0x11, 0xd0, 0xf4,
    0xe6, 0xbc, 0x68, 0x8b, 0x4d,
    /* b2 */
    0x71, 0x16, 0x9b, 0xe7, 0x33, 0x0b, 0x30, 0x38,
    0xed, 0xb0, 0x25, 0xf1
};

static const unsigned char glv_constants_secp224k1[] = {
    /* beta */
    0x01, 0xf1, 0x78, 0xff, 0xa4, 0xb1, 0x7c, 0x89,
    0xe6, 0xf7, 0x3a, 0xec, 0xe2, 0xaa, 0xd5, 0x7a,
    0xf4, 0xc0, 0xa7, 0x48, 0xb6, 0x3c, 0x83, 0x09,
    0x47, 0xb2, 0x7e, 0x04,
    /* a1 */
    0xb8, 0xad, 0xf1, 0x37, 0x8a, 0x6e, 0xb7, 0x34,
    0x09, 0xfa, 0x6c, 0x9c, 0x63, 0x7d,
    /* b1 */
    0x6b, 0x8c, 0xf0, 0x7d, 0x4c, 0xa7, 0x5c, 0x88,
    0x95, 0x7d, 0x9d, 0x67, 0x05, 0x91,
    /* a2 */
    0x6b, 0x8c, 0xf0, 0x7d, 0x4c, 0xa7, 0x5c, 0x88,
    0x95, 0x7d, 0x9d, 0x67, 0x05, 0x91,
    /* b2 */
    0x01, 0x24, 0x3a, 0xe1, 0xb4, 0xd7, 0x16, 0x13,
    0xbc, 0x9f, 0x78, 0x0a, 0x03, 0x69, 0x0e
};

static const unsigned char glv_constants_secp256k1[] = {
    /* beta */
    0x85, 0x16, 0x95, 0xd4, 0x9a, 0x83, 0xf8, 0xef,
    0x91, 0x9b, 0xb8, 0x61, 0x53, 0xcb, 0xcb, 0x16,
    0x63, 0x0f, 0xb6, 0x8a, 0xed, 0x0a, 0x76, 0x6a,
    0x3e, 0xc6, 0x93, 0xd6, 0x8e, 0x6a, 0xfa, 0x40,
    /* a1 */
    0xe4, 0x43, 0x7e, 0xd6, 0x01, 0x0e, 0x88, 0x28,
    0x6f, 0x54, 0x7f, 0xa9, 0x0a, 0xbf, 0xe4, 0xc3,
    /* b1 */
    0x30, 0x86, 0xd2, 0x21, 0xa7, 0xd4, 0x6b, 0xcd,
    0xe8, 0x6c, 0x90, 0xe4, 0x92, 0x84, 0xeb, 0x15,
    /* a2 */
    0x30, 0x86, 0xd2, 0x21, 0xa7, 0xd4, 0x6b, 0xcd,
    0xe8, 0x6c, 0x90, 0xe4, 0x92, 0x84, 0xeb, 0x15,
    /* b2 */
    0x01, 0x14, 0xca, 0x50, 0xf7, 0xa8, 0xe2, 0xf3,
    0xf6, 0x57, 0xc1, 0x10, 0x8d, 0x9d, 0x44, 0xcf,
    0xd8
};

int ec_GFp_glv_group_init(EC_GROUP *group)
{
    int ok;

    ok = ec_GFp_mont_group_init(group);
    group->custom_data = NULL;
    return ok;
}

#define GLV_CONSTANTS_FREE(g) do {                  \
    if (g->custom_data != NULL) {                   \
        int ZZ_i;                                   \
        BIGNUM **ZZ_c = (BIGNUM **)g->custom_data;  \
        for(ZZ_i=0; ZZ_i<5; ZZ_i++) {               \
            BN_free(ZZ_c[ZZ_i]);                    \
        }                                           \
        OPENSSL_free(g->custom_data);               \
        g->custom_data = NULL;                      \
    }                                               \
} while(0)

void ec_GFp_glv_group_finish(EC_GROUP *group)
{
    GLV_CONSTANTS_FREE(group);
    ec_GFp_mont_group_finish(group);
}

void ec_GFp_glv_group_clear_finish(EC_GROUP *group)
{
    int i;

    if (group->custom_data != NULL) {
        BIGNUM **constants = (BIGNUM **)group->custom_data;
        for (i = 0; i < 5; i++)
            BN_clear_free(constants[i]);
        OPENSSL_clear_free(group->custom_data, 5 * sizeof(BIGNUM *));
        group->custom_data = NULL;
    }
    ec_GFp_mont_group_clear_finish(group);
}

int ec_GFp_glv_group_copy(EC_GROUP *dest, const EC_GROUP *src)
{
    int i;

    if (!ec_GFp_mont_group_copy(dest, src))
        return 0;

    GLV_CONSTANTS_FREE(dest);

    if (src->custom_data == NULL)
        return 1;

    dest->custom_data = OPENSSL_zalloc(5 * sizeof(BIGNUM *));
    if (dest->custom_data == NULL)
        return 0;
    BIGNUM **destc = (BIGNUM **)dest->custom_data;
    BIGNUM **srcc = (BIGNUM **)src->custom_data;
    for (i = 0; i < 5; i++) {
        if ((destc[i] = BN_dup(srcc[i])) == NULL)
            goto err;
    }

    return 1;

 err:

    GLV_CONSTANTS_FREE(dest);
    return 0;
}
/**
 * Otherwise stock set_curve, but load these GLV constants based on NID:
 * 
 * beta = constants[0]
 * a1   = constants[1]
 * b1   = constants[2]
 * a2   = constants[3]
 * b2   = constants[4]
 */
int ec_GFp_glv_group_set_curve(EC_GROUP *group, const BIGNUM *p,
                               const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    int i;

    if (ec_GFp_mont_group_set_curve(group, p, a, b, ctx) == 0)
        return 0;

    GLV_CONSTANTS_FREE(group);

    group->custom_data = OPENSSL_zalloc(5 * sizeof(BIGNUM *));
    if (group->custom_data == NULL)
        return 0;
    BIGNUM **constants = (BIGNUM **)group->custom_data;
    for (i = 0; i < 5; i++) {
        if ((constants[i] = BN_new()) == NULL)
            goto err;
    }

    switch (group->curve_name) {
    case NID_secp160k1:
        BN_bin2bn(glv_constants_secp160k1 + 0, 20, constants[0]);
        BN_bin2bn(glv_constants_secp160k1 + 20, 10, constants[1]);
        BN_bin2bn(glv_constants_secp160k1 + 30, 10, constants[2]);
        BN_bin2bn(glv_constants_secp160k1 + 40, 11, constants[3]);
        BN_bin2bn(glv_constants_secp160k1 + 51, 10, constants[4]);
        break;
    case NID_secp192k1:
        BN_bin2bn(glv_constants_secp192k1 + 0, 24, constants[0]);
        BN_bin2bn(glv_constants_secp192k1 + 24, 12, constants[1]);
        BN_bin2bn(glv_constants_secp192k1 + 36, 12, constants[2]);
        BN_bin2bn(glv_constants_secp192k1 + 48, 13, constants[3]);
        BN_bin2bn(glv_constants_secp192k1 + 61, 12, constants[4]);
        break;
    case NID_secp224k1:
        BN_bin2bn(glv_constants_secp224k1 + 0, 28, constants[0]);
        BN_bin2bn(glv_constants_secp224k1 + 28, 14, constants[1]);
        BN_bin2bn(glv_constants_secp224k1 + 42, 14, constants[2]);
        BN_bin2bn(glv_constants_secp224k1 + 56, 14, constants[3]);
        BN_bin2bn(glv_constants_secp224k1 + 70, 15, constants[4]);
        break;
    case NID_secp256k1:
        BN_bin2bn(glv_constants_secp256k1 + 0, 32, constants[0]);
        BN_bin2bn(glv_constants_secp256k1 + 32, 16, constants[1]);
        BN_bin2bn(glv_constants_secp256k1 + 48, 16, constants[2]);
        BN_bin2bn(glv_constants_secp256k1 + 64, 16, constants[3]);
        BN_bin2bn(glv_constants_secp256k1 + 80, 17, constants[4]);
        break;
    default:
        goto err;
    }

    for (i = 0; i < 5; i++) {
        if (constants[i] == NULL)
            goto err;
    }

    /* encode beta parameter to curve's finite field */
    if (!group->meth->field_encode(group, constants[0], constants[0], ctx))
        goto err;

    return 1;

 err:

    GLV_CONSTANTS_FREE(group);
    return 0;
}

/**
 * Integer decomposition.
 * See 3.5 in "Guide to Elliptic Curve Cryptography"
 *
 * The alg is slightly re-arranged to keep all constants positive.
 *
 * Computes (k1, k2) s.t. scalar = k1 + k2 * lambda (mod n) holds, 
 * and (k1, k2) are roughly half the bit length of group order n.
 *
 * a1 = constants[1]
 * b1 = constants[2]
 * a2 = constants[3]
 * b2 = constants[4]
 *
 * @return 1 on success, 0 otherwise
 */
int ec_GFp_glv_decompose(const EC_GROUP *group, BIGNUM *k1, BIGNUM *k2,
                         const BIGNUM *scalar, BN_CTX *ctx)
{

    int ret = 0;

    BIGNUM *twok, *c1, *c2;

    if (group->custom_data == NULL)
        return 0;

    BIGNUM **constants = (BIGNUM **)group->custom_data;

    BN_CTX_start(ctx);

    do {
        twok = BN_CTX_get(ctx);
        c1 = BN_CTX_get(ctx);
        if ((c2 = BN_CTX_get(ctx)) == NULL)
            break;

        if (!BN_lshift1(twok, scalar))
            break;

        /* weird computation is for closest int rounding */
        /* c1 = (2*b2*k+r[0])/(2*r[0]) */
        /* c2 = (2*b1*k+r[0])/(2*r[0]) */
        if (!BN_mul(c1, twok, constants[4], ctx))
            break;
        if (!BN_add(c1, c1, group->order))
            break;
        if (!BN_div(c1, NULL, c1, group->order, ctx))
            break;
        if (!BN_rshift1(c1, c1))
            break;
        if (!BN_mul(c2, twok, constants[2], ctx))
            break;
        if (!BN_add(c2, c2, group->order))
            break;
        if (!BN_div(c2, NULL, c2, group->order, ctx))
            break;
        if (!BN_rshift1(c2, c2))
            break;

        /* k1 = k - (c1*a1 + c2*a2) */
        /* k2 = c1*b1 - c2*b2 */
        if (!BN_mul(k1, constants[1], c1, ctx))
            break;
        if (!BN_mul(k2, constants[3], c2, ctx))
            break;
        if (!BN_add(k1, k1, k2))
            break;
        if (!BN_sub(k1, scalar, k1))
            break;
        if (!BN_mul(c1, constants[2], c1, ctx))
            break;
        if (!BN_mul(c2, constants[4], c2, ctx))
            break;
        if (!BN_sub(k2, c1, c2))
            break;

        ret = 1;
    } while (0);

    BN_CTX_end(ctx);

    return ret;

}

/**
 * Computes the sum
 * scalar*group->generator + scalars[0]*points[0] + ... + scalars[num-1]*points[num-1]
 */
int ec_GFp_glv_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                   size_t num, const EC_POINT *points[],
                   const BIGNUM *scalars[], BN_CTX *ctx)
{

    /* use default stuff if we have precomp and it can help */
    if ((num == 0 && EC_GROUP_have_precompute_mult(group))
        || group->custom_data == NULL)
        return ec_wNAF_mul(group, r, scalar, num, points, scalars, ctx);

    int i, ret = 0;

    BIGNUM *tscalar = NULL;
    EC_POINT **tpoints = NULL;
    BIGNUM **tscalars = NULL;
    BIGNUM **constants = (BIGNUM **)group->custom_data;

    BN_CTX_start(ctx);

    /* setup some arrays, decompose scalar if present, apply endomorphism */
    if (scalar == NULL) {
        if ((tpoints = OPENSSL_malloc(2 * num * sizeof(EC_POINT *))) == NULL)
            goto err;
        if ((tscalars = OPENSSL_malloc(2 * num * sizeof(BIGNUM *))) == NULL)
            goto err;
    } else {
        if ((tpoints =
             OPENSSL_malloc((2 * num + 1) * sizeof(EC_POINT *))) == NULL)
            goto err;
        if ((tscalars =
             OPENSSL_malloc((2 * num + 1) * sizeof(BIGNUM *))) == NULL)
            goto err;
        tscalar = BN_CTX_get(ctx);
        if ((tscalars[2 * num] = BN_CTX_get(ctx)) == NULL)
            goto err;
        if ((tpoints[2 * num] = EC_POINT_new(group)) == NULL)
            goto err;
        if (!EC_POINT_copy(tpoints[2 * num], EC_GROUP_get0_generator(group)))
            goto err;
        if (!group->
            meth->field_mul(group, tpoints[2 * num]->X, tpoints[2 * num]->X,
                            constants[0], ctx))
            goto err;
        if (!ec_GFp_glv_decompose
            (group, tscalar, tscalars[2 * num], scalar, ctx))
            goto err;
    }

    /* decompose all the other scalars and apply the endomorphism */
    for (i = 0; i < num; i++) {
        tpoints[2 * i] = *((EC_POINT **)points + i);
        if ((tpoints[2 * i + 1] = EC_POINT_new(group)) == NULL)
            goto err;
        if (!EC_POINT_copy(tpoints[2 * i + 1], tpoints[2 * i]))
            goto err;
        if (!group->
            meth->field_mul(group, tpoints[2 * i + 1]->X,
                            tpoints[2 * i + 1]->X, constants[0], ctx))
            goto err;
        tscalars[2 * i] = BN_CTX_get(ctx);
        if ((tscalars[2 * i + 1] = BN_CTX_get(ctx)) == NULL)
            goto err;
        if (!ec_GFp_glv_decompose
            (group, tscalars[2 * i], tscalars[2 * i + 1], scalars[i], ctx))
            goto err;
    }

    /* call into the multi scalar mult routine with new parameters */
    if (scalar == NULL) {
        ret =
            ec_wNAF_mul(group, r, scalar, 2 * num, (const EC_POINT **)tpoints,
                        (const BIGNUM **)tscalars, ctx);
    } else {
        ret =
            ec_wNAF_mul(group, r, tscalar, 2 * num + 1,
                        (const EC_POINT **)tpoints, (const BIGNUM **)tscalars,
                        ctx);
    }

 err:

    /* cleanup */
    if (tpoints != NULL) {
        for (i = 0; i < num; i++) {
            EC_POINT_free(tpoints[2 * i + 1]);
        }
        if (scalar != NULL) {
            EC_POINT_free(tpoints[2 * num]);
        }
    }

    BN_CTX_end(ctx);

    OPENSSL_free(tpoints);
    OPENSSL_free(tscalars);

    return ret;
}

int ec_GFp_glv_precompute_mult(EC_GROUP *group, BN_CTX *ctx)
{
    return ec_wNAF_precompute_mult(group, ctx);
}

int ec_GFp_glv_have_precompute_mult(const EC_GROUP *group)
{
    return ec_wNAF_have_precompute_mult(group);
}

const EC_METHOD *EC_GFp_glv_method(void)
{
    static const EC_METHOD ret = {
        EC_FLAGS_DEFAULT_OCT,
        NID_X9_62_prime_field,
        ec_GFp_glv_group_init,
        ec_GFp_glv_group_finish,
        ec_GFp_glv_group_clear_finish,
        ec_GFp_glv_group_copy,
        ec_GFp_glv_group_set_curve,
        ec_GFp_simple_group_get_curve,
        ec_GFp_simple_group_get_degree,
        ec_group_simple_order_bits, /* group_order_bits */
        ec_GFp_simple_group_check_discriminant,
        ec_GFp_simple_point_init,
        ec_GFp_simple_point_finish,
        ec_GFp_simple_point_clear_finish,
        ec_GFp_simple_point_copy,
        ec_GFp_simple_point_set_to_infinity,
        ec_GFp_simple_set_Jprojective_coordinates_GFp,
        ec_GFp_simple_get_Jprojective_coordinates_GFp,
        ec_GFp_simple_point_set_affine_coordinates,
        ec_GFp_simple_point_get_affine_coordinates,
        0, 0, 0,
        ec_GFp_simple_add,
        ec_GFp_simple_dbl,
        ec_GFp_simple_invert,
        ec_GFp_simple_is_at_infinity,
        ec_GFp_simple_is_on_curve,
        ec_GFp_simple_cmp,
        ec_GFp_simple_make_affine,
        ec_GFp_simple_points_make_affine,
        ec_GFp_glv_mul,
        ec_GFp_glv_precompute_mult,
        ec_GFp_glv_have_precompute_mult,
        ec_GFp_mont_field_mul,
        ec_GFp_mont_field_sqr,
        0, /* field_div */
        ec_GFp_mont_field_encode,
        ec_GFp_mont_field_decode,
        ec_GFp_mont_field_set_to_one,
        ec_key_simple_priv2oct,
        ec_key_simple_oct2priv,
        0, /* set private */
        ec_key_simple_generate_key,
        ec_key_simple_check_key,
        ec_key_simple_generate_public_key,
        0, /* keycopy */
        0, /* keyfinish */
        ecdh_simple_compute_key
    };

    return &ret;
}
