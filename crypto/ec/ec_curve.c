/*
 * Copyright 2002-2025 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
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
#include "ec_local.h"
#include "../bn/bn_local.h"

#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/opensslconf.h>
#include "internal/nelem.h"

typedef struct {
    int field_type, /* either NID_X9_62_prime_field or
                     * NID_X9_62_characteristic_two_field */
        seed_len, param_len;
    unsigned int cofactor; /* promoted to BN_ULONG */
} EC_CURVE_DATA;

typedef struct _ec_list_element_st {
    int nid;
    const EC_CURVE_DATA *data;
    const EC_METHOD *(*meth)(void);
    const char *comment;
} ec_list_element;

/*
 * Method selectors for curves that have an optimized EC_METHOD.  The
 * generated curve_list entries reference these by name, so the selection
 * preprocessor dance lives here rather than in the table.
 */
#if !defined(OPENSSL_NO_EC_NISTP_64_GCC_128)
#define ec_method_nistp224 EC_GFp_nistp224_method
#else
#define ec_method_nistp224 0
#endif
#if defined(ECP_NISTZ256_ASM)
#define ec_method_nistz256 EC_GFp_nistz256_method
#elif defined(S390X_EC_ASM)
#define ec_method_nistz256 EC_GFp_s390x_nistp256_method
#elif !defined(OPENSSL_NO_EC_NISTP_64_GCC_128)
#define ec_method_nistz256 EC_GFp_nistp256_method
#else
#define ec_method_nistz256 0
#endif
#if defined(S390X_EC_ASM)
#define ec_method_nistp384 EC_GFp_s390x_nistp384_method
#elif !defined(OPENSSL_NO_EC_NISTP_64_GCC_128)
#define ec_method_nistp384 ossl_ec_GFp_nistp384_method
#else
#define ec_method_nistp384 0
#endif
#if defined(S390X_EC_ASM)
#define ec_method_nistp521 EC_GFp_s390x_nistp521_method
#elif !defined(OPENSSL_NO_EC_NISTP_64_GCC_128)
#define ec_method_nistp521 EC_GFp_nistp521_method
#else
#define ec_method_nistp521 0
#endif
#ifdef ECP_SM2P256_ASM
#define ec_method_sm2p256 EC_GFp_sm2p256_method
#else
#define ec_method_sm2p256 0
#endif

#include "ec_curves.inc"

#define curve_list_length OSSL_NELEM(curve_list)

static const ec_list_element *ec_curve_nid2curve(int nid)
{
    size_t i;

    if (nid <= 0)
        return NULL;

    for (i = 0; i < curve_list_length; i++) {
        if (curve_list[i].nid == nid)
            return &curve_list[i];
    }
    return NULL;
}

static EC_GROUP *ec_group_new_from_data(OSSL_LIB_CTX *libctx,
    const char *propq,
    const ec_list_element curve)
{
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL;
    BN_CTX *ctx = NULL;
    const EC_STATIC_BIGNUM *sb = NULL;
    int ok = 0;
    int seed_len;
    const EC_METHOD *meth;
    const EC_CURVE_DATA *data;
    const unsigned char *params;

    /* If no curve data curve method must handle everything */
    if (curve.data == NULL)
        return ossl_ec_group_new_ex(libctx, propq,
            curve.meth != NULL ? curve.meth() : NULL);

    if ((ctx = BN_CTX_new_ex(libctx)) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }

    data = curve.data;
    seed_len = data->seed_len;
    params = (const unsigned char *)(data + 1); /* skip header */

    if (curve.meth != NULL) {
        meth = curve.meth();
        if ((group = ossl_ec_group_new_ex(libctx, propq, meth)) == NULL) {
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto err;
        }
        if (group->meth->group_full_init != NULL) {
            if (!group->meth->group_full_init(group, params)) {
                ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
                goto err;
            }
            EC_GROUP_set_curve_name(group, curve.nid);
            BN_CTX_free(ctx);
            return group;
        }
    }

    params += seed_len; /* skip seed */

    if (!ec_static_lookup(curve.nid, &sb)) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }

    if (group != NULL) {
        if (group->meth->group_set_curve(group, sb->p, sb->a, sb->b, ctx) == 0) {
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto err;
        }
    } else if (data->field_type == NID_X9_62_prime_field) {
        if ((group = EC_GROUP_new_curve_GFp(sb->p, sb->a, sb->b, ctx)) == NULL) {
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else { /* field_type ==
            * NID_X9_62_characteristic_two_field */

        if ((group = EC_GROUP_new_curve_GF2m(sb->p, sb->a, sb->b, ctx)) == NULL) {
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto err;
        }
    }
#endif

    EC_GROUP_set_curve_name(group, curve.nid);

    if ((P = EC_POINT_new(group)) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }

    if (!EC_POINT_set_affine_coordinates(group, P, sb->x, sb->y, ctx)) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }
    if (!EC_GROUP_set_generator(group, P, sb->order, sb->cof)) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }
    if (seed_len) {
        if (!EC_GROUP_set_seed(group, params - seed_len, seed_len)) {
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto err;
        }
    }

#ifndef FIPS_MODULE
    if (EC_GROUP_get_asn1_flag(group) == OPENSSL_EC_NAMED_CURVE) {
        /*
         * Some curves don't have an associated OID: for those we should not
         * default to `OPENSSL_EC_NAMED_CURVE` encoding of parameters and
         * instead set the ASN1 flag to `OPENSSL_EC_EXPLICIT_CURVE`.
         *
         * Note that `OPENSSL_EC_NAMED_CURVE` is set as the default ASN1 flag on
         * `EC_GROUP_new()`, when we don't have enough elements to determine if
         * an OID for the curve name actually exists.
         * We could implement this check on `EC_GROUP_set_curve_name()` but
         * overloading the simple setter with this lookup could have a negative
         * performance impact and unexpected consequences.
         */
        ASN1_OBJECT *asn1obj = OBJ_nid2obj(curve.nid);

        if (asn1obj == NULL) {
            ERR_raise(ERR_LIB_EC, ERR_R_OBJ_LIB);
            goto err;
        }
        if (OBJ_length(asn1obj) == 0)
            EC_GROUP_set_asn1_flag(group, OPENSSL_EC_EXPLICIT_CURVE);

        ASN1_OBJECT_free(asn1obj);
    }
#else
    /*
     * Inside the FIPS module we do not support explicit curves anyway
     * so the above check is not necessary.
     *
     * Skipping it is also necessary because `OBJ_length()` and
     * `ASN1_OBJECT_free()` are not available within the FIPS module
     * boundaries.
     */
#endif

    ok = 1;
err:
    if (!ok) {
        EC_GROUP_free(group);
        group = NULL;
    }
    EC_POINT_free(P);
    BN_CTX_free(ctx);
    return group;
}

EC_GROUP *EC_GROUP_new_by_curve_name_ex(OSSL_LIB_CTX *libctx, const char *propq,
    int nid)
{
    EC_GROUP *ret = NULL;
    const ec_list_element *curve;

    if ((curve = ec_curve_nid2curve(nid)) == NULL
        || (ret = ec_group_new_from_data(libctx, propq, *curve)) == NULL) {
#ifndef FIPS_MODULE
        ERR_raise_data(ERR_LIB_EC, EC_R_UNKNOWN_GROUP,
            "name=%s", OBJ_nid2sn(nid));
#else
        ERR_raise(ERR_LIB_EC, EC_R_UNKNOWN_GROUP);
#endif
        return NULL;
    }

    return ret;
}

#ifndef FIPS_MODULE
EC_GROUP *EC_GROUP_new_by_curve_name(int nid)
{
    return EC_GROUP_new_by_curve_name_ex(NULL, NULL, nid);
}
#endif

size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems)
{
    size_t i, min;

    if (r == NULL || nitems == 0)
        return curve_list_length;

    min = nitems < curve_list_length ? nitems : curve_list_length;

    for (i = 0; i < min; i++) {
        r[i].nid = curve_list[i].nid;
        r[i].comment = curve_list[i].comment;
    }

    return curve_list_length;
}

const char *EC_curve_nid2nist(int nid)
{
    return ossl_ec_curve_nid2nist_int(nid);
}

int EC_curve_nist2nid(const char *name)
{
    return ossl_ec_curve_nist2nid_int(name);
}

#define NUM_BN_FIELDS 6
/*
 * Validates EC domain parameter data for known named curves.
 * This can be used when a curve is loaded explicitly (without a curve
 * name) or to validate that domain parameters have not been modified.
 *
 * Returns: The nid associated with the found named curve, or NID_undef
 *          if not found. If there was an error it returns -1.
 */
int ossl_ec_curve_nid_from_params(const EC_GROUP *group, BN_CTX *ctx)
{
    int ret = -1, nid, len, field_type, param_len;
    size_t i, seed_len;
    const unsigned char *seed, *params_seed, *params;
    unsigned char *param_bytes = NULL;
    const EC_CURVE_DATA *data;
    const EC_POINT *generator = NULL;
    const BIGNUM *cofactor = NULL;
    /* An array of BIGNUMs for (p, a, b, x, y, order) */
    BIGNUM *bn[NUM_BN_FIELDS] = { NULL, NULL, NULL, NULL, NULL, NULL };

    /* Use the optional named curve nid as a search field */
    nid = EC_GROUP_get_curve_name(group);
    field_type = EC_GROUP_get_field_type(group);
    seed_len = EC_GROUP_get_seed_len(group);
    seed = EC_GROUP_get0_seed(group);
    cofactor = EC_GROUP_get0_cofactor(group);

    BN_CTX_start(ctx);

    /*
     * The built-in curves contains data fields (p, a, b, x, y, order) that are
     * all zero-padded to be the same size. The size of the padding is
     * determined by either the number of bytes in the field modulus (p) or the
     * EC group order, whichever is larger.
     */
    param_len = BN_num_bytes(group->order);
    len = BN_num_bytes(group->field);
    if (len > param_len)
        param_len = len;

    /* Allocate space to store the padded data for (p, a, b, x, y, order)  */
    param_bytes = OPENSSL_malloc_array(NUM_BN_FIELDS, param_len);
    if (param_bytes == NULL)
        goto end;

    /* Create the bignums */
    for (i = 0; i < NUM_BN_FIELDS; ++i) {
        if ((bn[i] = BN_CTX_get(ctx)) == NULL)
            goto end;
    }
    /*
     * Fill in the bn array with the same values as the internal curves
     * i.e. the values are p, a, b, x, y, order.
     */
    /* Get p, a & b */
    if (!(EC_GROUP_get_curve(group, bn[0], bn[1], bn[2], ctx)
            && ((generator = EC_GROUP_get0_generator(group)) != NULL)
            /* Get x & y */
            && EC_POINT_get_affine_coordinates(group, generator, bn[3], bn[4], ctx)
            /* Get order */
            && EC_GROUP_get_order(group, bn[5], ctx)))
        goto end;

    /*
     * Convert the bignum array to bytes that are joined together to form
     * a single buffer that contains data for all fields.
     * (p, a, b, x, y, order) are all zero padded to be the same size.
     */
    for (i = 0; i < NUM_BN_FIELDS; ++i) {
        if (BN_bn2binpad(bn[i], &param_bytes[i * param_len], param_len) <= 0)
            goto end;
    }

    for (i = 0; i < curve_list_length; i++) {
        const ec_list_element curve = curve_list[i];

        data = curve.data;
        /* Get the raw order byte data */
        params_seed = (const unsigned char *)(data + 1); /* skip header */
        params = params_seed + data->seed_len;

        /* Look for unique fields in the fixed curve data */
        if (data->field_type == field_type
            && param_len == data->param_len
            && (nid <= 0 || nid == curve.nid)
            /* check the optional cofactor (ignore if its zero) */
            && (cofactor == NULL || BN_is_zero(cofactor)
                || BN_is_word(cofactor, (const BN_ULONG)curve.data->cofactor))
            /* Check the optional seed (ignore if its not set) */
            && (data->seed_len == 0 || seed_len == 0
                || ((size_t)data->seed_len == seed_len
                    && memcmp(params_seed, seed, seed_len) == 0))
            /* Check that the groups params match the built-in curve params */
            && memcmp(param_bytes, params, param_len * NUM_BN_FIELDS)
                == 0) {
            ret = curve.nid;
            goto end;
        }
    }
    /* Gets here if the group was not found */
    ret = NID_undef;
end:
    OPENSSL_free(param_bytes);
    BN_CTX_end(ctx);
    return ret;
}
