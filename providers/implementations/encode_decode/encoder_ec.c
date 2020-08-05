/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include "crypto/ec.h"
#include "prov/bio.h"             /* ossl_prov_bio_printf() */
#include "prov/implementations.h" /* ec_keymgmt_functions */
#include "prov/providercommonerr.h" /* PROV_R_MISSING_OID */
#include "encoder_local.h"

void ec_get_new_free_import(OSSL_FUNC_keymgmt_new_fn **ec_new,
                            OSSL_FUNC_keymgmt_free_fn **ec_free,
                            OSSL_FUNC_keymgmt_import_fn **ec_import)
{
    *ec_new = ossl_prov_get_keymgmt_new(ec_keymgmt_functions);
    *ec_free = ossl_prov_get_keymgmt_free(ec_keymgmt_functions);
    *ec_import = ossl_prov_get_keymgmt_import(ec_keymgmt_functions);
}

static int ossl_prov_print_ec_param_explicit_curve(BIO *out,
                                                   const EC_GROUP *group,
                                                   BN_CTX *ctx)
{
    const char *plabel = "Prime:";
    BIGNUM *p = NULL, *a = NULL, *b = NULL;

    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    if (b == NULL
        || !EC_GROUP_get_curve(group, p, a, b, ctx))
        return 0;

    if (EC_GROUP_get_field_type(group) == NID_X9_62_characteristic_two_field) {
        int basis_type = EC_GROUP_get_basis_type(group);

        /* print the 'short name' of the base type OID */
        if (basis_type == NID_undef
            || BIO_printf(out, "Basis Type: %s\n", OBJ_nid2sn(basis_type)) <= 0)
            return 0;
        plabel = "Polynomial:";
    }
    return ossl_prov_print_labeled_bignum(out, plabel, p)
           && ossl_prov_print_labeled_bignum(out, "A:   ", a)
           && ossl_prov_print_labeled_bignum(out, "B:   ", b);
}

static int ossl_prov_print_ec_param_explicit_gen(BIO *out,
                                                 const EC_GROUP *group,
                                                 BN_CTX *ctx)
{
    const EC_POINT *point = NULL;
    BIGNUM *gen = NULL;
    const char *glabel = NULL;
    point_conversion_form_t form;

    form = EC_GROUP_get_point_conversion_form(group);
    point = EC_GROUP_get0_generator(group);
    gen = BN_CTX_get(ctx);

    if (gen == NULL
        || point == NULL
        || EC_POINT_point2bn(group, point, form, gen, ctx) == NULL)
        return 0;

    if (gen != NULL) {
        switch (form) {
        case POINT_CONVERSION_COMPRESSED:
           glabel = "Generator (compressed):";
           break;
        case POINT_CONVERSION_UNCOMPRESSED:
            glabel = "Generator (uncompressed):";
            break;
        case POINT_CONVERSION_HYBRID:
            glabel = "Generator (hybrid):";
            break;
        default:
            return 0;
        }
        return ossl_prov_print_labeled_bignum(out, glabel, gen);
    }
    return 1;
}

/* Print explicit parameters */
static int ossl_prov_print_ec_param_explicit(BIO *out, const EC_GROUP *group,
                                             OPENSSL_CTX *libctx)
{
    int ret = 0, tmp_nid;
    BN_CTX *ctx = NULL;
    const BIGNUM *order = NULL, *cofactor = NULL;
    const unsigned char *seed;
    size_t seed_len = 0;

    ctx = BN_CTX_new_ex(libctx);
    if (ctx == NULL)
        return 0;
    BN_CTX_start(ctx);

    tmp_nid = EC_GROUP_get_field_type(group);
    order = EC_GROUP_get0_order(group);
    if (order == NULL)
        goto err;

    seed = EC_GROUP_get0_seed(group);
    if (seed != NULL)
        seed_len = EC_GROUP_get_seed_len(group);
    cofactor = EC_GROUP_get0_cofactor(group);

    /* print the 'short name' of the field type */
    if (BIO_printf(out, "Field Type: %s\n", OBJ_nid2sn(tmp_nid)) <= 0
        || !ossl_prov_print_ec_param_explicit_curve(out, group, ctx)
        || !ossl_prov_print_ec_param_explicit_gen(out, group, ctx)
        || !ossl_prov_print_labeled_bignum(out, "Order: ", order)
        || (cofactor != NULL
            && !ossl_prov_print_labeled_bignum(out, "Cofactor: ", cofactor))
        || (seed != NULL
            && !ossl_prov_print_labeled_buf(out, "Seed:", seed, seed_len)))
        goto err;
    ret = 1;
err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

static int ossl_prov_print_ec_param(BIO *out, const EC_GROUP *group,
                                    OPENSSL_CTX *libctx)
{
    if (EC_GROUP_get_asn1_flag(group) & OPENSSL_EC_NAMED_CURVE) {
        const char *curve_name;
        int curve_nid = EC_GROUP_get_curve_name(group);

        /* Explicit parameters */
        if (curve_nid == NID_undef)
            return 0;

        if (BIO_printf(out, "%s: %s\n", "ASN1 OID", OBJ_nid2sn(curve_nid)) <= 0)
            return 0;

        /* TODO(3.0): Only named curves are currently supported */
        curve_name = EC_curve_nid2nist(curve_nid);
        return (curve_name == NULL
                || BIO_printf(out, "%s: %s\n", "NIST CURVE", curve_name) > 0);
    } else {
        return ossl_prov_print_ec_param_explicit(out, group, libctx);
    }
}

int ossl_prov_print_eckey(BIO *out, EC_KEY *eckey, enum ec_print_type type)
{
    int ret = 0;
    const char *type_label = NULL;
    unsigned char *priv = NULL, *pub = NULL;
    size_t priv_len = 0, pub_len = 0;
    const EC_GROUP *group;

    if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL)
        goto null_err;

    switch (type) {
    case ec_print_priv:
        type_label = "Private-Key";
        break;
    case ec_print_pub:
        type_label = "Public-Key";
        break;
    case ec_print_params:
        type_label = "EC-Parameters";
        break;
    }

    if (type == ec_print_priv) {
        const BIGNUM *priv_key = EC_KEY_get0_private_key(eckey);

        if (priv_key == NULL)
            goto null_err;
        priv_len = EC_KEY_priv2buf(eckey, &priv);
        if (priv_len == 0)
            goto err;
    }

    if (type == ec_print_priv || type == ec_print_pub) {
        const EC_POINT *pub_pt = EC_KEY_get0_public_key(eckey);

        if (pub_pt == NULL)
            goto null_err;

        pub_len = EC_KEY_key2buf(eckey, EC_KEY_get_conv_form(eckey), &pub, NULL);
        if (pub_len == 0)
            goto err;
    }

    if (BIO_printf(out, "%s: (%d bit)\n", type_label,
                   EC_GROUP_order_bits(group)) <= 0)
        goto err;
    if (priv != NULL
        && !ossl_prov_print_labeled_buf(out, "priv:", priv, priv_len))
        goto err;
    if (pub != NULL
        && !ossl_prov_print_labeled_buf(out, "pub:", pub, pub_len))
        goto err;
    ret = ossl_prov_print_ec_param(out, group, ec_key_get_libctx(eckey));
err:
    OPENSSL_clear_free(priv, priv_len);
    OPENSSL_free(pub);
    return ret;
null_err:
    ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
    goto err;
}

static int ossl_prov_prepare_ec_explicit_params(const void *eckey,
                                                void **pstr, int *pstrtype)
{
    ASN1_STRING *params = ASN1_STRING_new();

    if (params == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    params->length = i2d_ECParameters(eckey, &params->data);
    if (params->length <= 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        ASN1_STRING_free(params);
        return 0;
    }

    *pstrtype = V_ASN1_SEQUENCE;
    *pstr = params;
    return 1;
}

int ossl_prov_prepare_ec_params(const void *eckey, int nid,
                                void **pstr, int *pstrtype)
{
    int curve_nid;
    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    ASN1_OBJECT *params = NULL;

    if (group == NULL)
        return 0;
    curve_nid = EC_GROUP_get_curve_name(group);
    if (curve_nid != NID_undef) {
        params = OBJ_nid2obj(curve_nid);
        if (params == NULL)
            return 0;
    }

    if (curve_nid != NID_undef
        && (EC_GROUP_get_asn1_flag(group) & OPENSSL_EC_NAMED_CURVE)) {
        if (OBJ_length(params) == 0) {
            /* Some curves might not have an associated OID */
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_OID);
            ASN1_OBJECT_free(params);
            return 0;
        }
        *pstr = params;
        *pstrtype = V_ASN1_OBJECT;
        return 1;
    } else {
        return ossl_prov_prepare_ec_explicit_params(eckey, pstr, pstrtype);
    }
}

int ossl_prov_ec_pub_to_der(const void *eckey, unsigned char **pder)
{
    return i2o_ECPublicKey(eckey, pder);
}

int ossl_prov_ec_priv_to_der(const void *veckey, unsigned char **pder)
{
    EC_KEY *eckey = (EC_KEY *)veckey;
    unsigned int old_flags;
    int ret = 0;

    /*
     * For PKCS8 the curve name appears in the PKCS8_PRIV_KEY_INFO object
     * as the pkeyalg->parameter field. (For a named curve this is an OID)
     * The pkey field is an octet string that holds the encoded
     * ECPrivateKey SEQUENCE with the optional parameters field omitted.
     * We omit this by setting the EC_PKEY_NO_PARAMETERS flag.
     */
    old_flags = EC_KEY_get_enc_flags(eckey); /* save old flags */
    EC_KEY_set_enc_flags(eckey, old_flags | EC_PKEY_NO_PARAMETERS);
    ret = i2d_ECPrivateKey(eckey, pder);
    EC_KEY_set_enc_flags(eckey, old_flags); /* restore old flags */
    return ret; /* return the length of the der encoded data */
}
