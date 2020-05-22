/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * ECDH/ECDSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include "crypto/bn.h"
#include "crypto/ec.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/providercommonerr.h"
#include "prov/provider_ctx.h"
#include "internal/param_build_set.h"

static OSSL_OP_keymgmt_new_fn ec_newdata;
static OSSL_OP_keymgmt_gen_init_fn ec_gen_init;
static OSSL_OP_keymgmt_gen_set_template_fn ec_gen_set_template;
static OSSL_OP_keymgmt_gen_set_params_fn ec_gen_set_params;
static OSSL_OP_keymgmt_gen_settable_params_fn ec_gen_settable_params;
static OSSL_OP_keymgmt_gen_fn ec_gen;
static OSSL_OP_keymgmt_gen_cleanup_fn ec_gen_cleanup;
static OSSL_OP_keymgmt_free_fn ec_freedata;
static OSSL_OP_keymgmt_get_params_fn ec_get_params;
static OSSL_OP_keymgmt_gettable_params_fn ec_gettable_params;
static OSSL_OP_keymgmt_set_params_fn ec_set_params;
static OSSL_OP_keymgmt_settable_params_fn ec_settable_params;
static OSSL_OP_keymgmt_has_fn ec_has;
static OSSL_OP_keymgmt_match_fn ec_match;
static OSSL_OP_keymgmt_validate_fn ec_validate;
static OSSL_OP_keymgmt_import_fn ec_import;
static OSSL_OP_keymgmt_import_types_fn ec_import_types;
static OSSL_OP_keymgmt_export_fn ec_export;
static OSSL_OP_keymgmt_export_types_fn ec_export_types;
static OSSL_OP_keymgmt_query_operation_name_fn ec_query_operation_name;

#define EC_DEFAULT_MD "SHA256"
#define EC_POSSIBLE_SELECTIONS                                                 \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)

static
const char *ec_query_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_KEYEXCH:
        return "ECDH";
    case OSSL_OP_SIGNATURE:
        return "ECDSA";
    }
    return NULL;
}

static ossl_inline
int domparams_to_params(const EC_KEY *ec, OSSL_PARAM_BLD *tmpl,
                        OSSL_PARAM params[])
{
    const EC_GROUP *ecg;
    int curve_nid;

    if (ec == NULL)
        return 0;

    ecg = EC_KEY_get0_group(ec);
    if (ecg == NULL)
        return 0;

    curve_nid = EC_GROUP_get_curve_name(ecg);

    if (curve_nid == NID_undef) {
        /* TODO(3.0): should we support explicit parameters curves? */
        return 0;
    } else {
        /* named curve */
        const char *curve_name = NULL;

        if ((curve_name = ec_curve_nid2name(curve_nid)) == NULL)
            return 0;
        if (!ossl_param_build_set_utf8_string(tmpl, params,
                                              OSSL_PKEY_PARAM_EC_NAME,
                                              curve_name))

            return 0;
    }

    return 1;
}

/*
 * Callers of key_to_params MUST make sure that domparams_to_params is also
 * called!
 *
 * This function only exports the bare keypair, domain parameters and other
 * parameters are exported separately.
 */
static ossl_inline
int key_to_params(const EC_KEY *eckey, OSSL_PARAM_BLD *tmpl,
                  OSSL_PARAM params[], int include_private,
                  unsigned char **pub_key)
{
    const BIGNUM *priv_key = NULL;
    const EC_POINT *pub_point = NULL;
    const EC_GROUP *ecg = NULL;
    size_t pub_key_len = 0;
    int ret = 0;
    BN_CTX *bnctx = NULL;

    if (eckey == NULL
        || (ecg = EC_KEY_get0_group(eckey)) == NULL)
        return 0;

    priv_key = EC_KEY_get0_private_key(eckey);
    pub_point = EC_KEY_get0_public_key(eckey);

    if (pub_point != NULL) {
        /*
         * EC_POINT_point2buf() can generate random numbers in some
         * implementations so we need to ensure we use the correct libctx.
         */
        bnctx = BN_CTX_new_ex(ec_key_get_libctx(eckey));
        if (bnctx == NULL)
            goto err;

        /* convert pub_point to a octet string according to the SECG standard */
        if ((pub_key_len = EC_POINT_point2buf(ecg, pub_point,
                                              POINT_CONVERSION_COMPRESSED,
                                              pub_key, bnctx)) == 0
            || !ossl_param_build_set_octet_string(tmpl, params,
                                                  OSSL_PKEY_PARAM_PUB_KEY,
                                                  *pub_key, pub_key_len))
            goto err;
    }

    if (priv_key != NULL && include_private) {
        size_t sz;
        int ecbits;

        /*
         * Key import/export should never leak the bit length of the secret
         * scalar in the key.
         *
         * For this reason, on export we use padded BIGNUMs with fixed length.
         *
         * When importing we also should make sure that, even if short lived,
         * the newly created BIGNUM is marked with the BN_FLG_CONSTTIME flag as
         * soon as possible, so that any processing of this BIGNUM might opt for
         * constant time implementations in the backend.
         *
         * Setting the BN_FLG_CONSTTIME flag alone is never enough, we also have
         * to preallocate the BIGNUM internal buffer to a fixed public size big
         * enough that operations performed during the processing never trigger
         * a realloc which would leak the size of the scalar through memory
         * accesses.
         *
         * Fixed Length
         * ------------
         *
         * The order of the large prime subgroup of the curve is our choice for
         * a fixed public size, as that is generally the upper bound for
         * generating a private key in EC cryptosystems and should fit all valid
         * secret scalars.
         *
         * For padding on export we just use the bit length of the order
         * converted to bytes (rounding up).
         *
         * For preallocating the BIGNUM storage we look at the number of "words"
         * required for the internal representation of the order, and we
         * preallocate 2 extra "words" in case any of the subsequent processing
         * might temporarily overflow the order length.
         */
        ecbits = EC_GROUP_order_bits(ecg);
        if (ecbits <= 0)
            goto err;
        sz = (ecbits + 7 ) / 8;

        if (!ossl_param_build_set_bn_pad(tmpl, params,
                                         OSSL_PKEY_PARAM_PRIV_KEY,
                                         priv_key, sz))
            goto err;
    }
    ret = 1;
 err:
    BN_CTX_free(bnctx);
    return ret;
}

static ossl_inline
int otherparams_to_params(const EC_KEY *ec, OSSL_PARAM_BLD *tmpl,
                          OSSL_PARAM params[])
{
    int ecdh_cofactor_mode = 0;

    if (ec == NULL)
        return 0;

    ecdh_cofactor_mode =
        (EC_KEY_get_flags(ec) & EC_FLAG_COFACTOR_ECDH) ? 1 : 0;
    return ossl_param_build_set_int(tmpl, params,
                                    OSSL_PKEY_PARAM_USE_COFACTOR_ECDH,
                                    ecdh_cofactor_mode);
}

static
void *ec_newdata(void *provctx)
{
    return EC_KEY_new_ex(PROV_LIBRARY_CONTEXT_OF(provctx));
}

static
void ec_freedata(void *keydata)
{
    EC_KEY_free(keydata);
}

static
int ec_has(void *keydata, int selection)
{
    EC_KEY *ec = keydata;
    int ok = 0;

    if (ec != NULL) {
        if ((selection & EC_POSSIBLE_SELECTIONS) != 0)
            ok = 1;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && (EC_KEY_get0_public_key(ec) != NULL);
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && (EC_KEY_get0_private_key(ec) != NULL);
        if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
            ok = ok && (EC_KEY_get0_group(ec) != NULL);
        /*
         * We consider OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS to always be
         * available, so no extra check is needed other than the previous one
         * against EC_POSSIBLE_SELECTIONS.
         */
    }
    return ok;
}

static int ec_match(const void *keydata1, const void *keydata2, int selection)
{
    const EC_KEY *ec1 = keydata1;
    const EC_KEY *ec2 = keydata2;
    const EC_GROUP *group_a = EC_KEY_get0_group(ec1);
    const EC_GROUP *group_b = EC_KEY_get0_group(ec2);
    int ok = 1;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && group_a != NULL && group_b != NULL
            && EC_GROUP_cmp(group_a, group_b, NULL) == 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        const BIGNUM *pa = EC_KEY_get0_private_key(ec1);
        const BIGNUM *pb = EC_KEY_get0_private_key(ec2);

        ok = ok && BN_cmp(pa, pb) == 0;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        const EC_POINT *pa = EC_KEY_get0_public_key(ec1);
        const EC_POINT *pb = EC_KEY_get0_public_key(ec2);

        ok = ok && EC_POINT_cmp(group_b, pa, pb, NULL);
    }
    return ok;
}

static
int ec_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    EC_KEY *ec = keydata;
    int ok = 1;

    if (ec == NULL)
        return 0;

    /*
     * In this implementation, we can export/import only keydata in the
     * following combinations:
     *   - domain parameters only
     *   - public key with associated domain parameters (+optional other params)
     *   - private key with associated public key and domain parameters
     *         (+optional other params)
     *
     * This means:
     *   - domain parameters must always be requested
     *   - private key must be requested alongside public key
     *   - other parameters must be requested only alongside a key
     */
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
            && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0
            && (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && ec_key_domparams_fromdata(ec, params);
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private =
            selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

        ok = ok && ec_key_fromdata(ec, params, include_private);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
        ok = ok && ec_key_otherparams_fromdata(ec, params);

    return ok;
}

static
int ec_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
              void *cbarg)
{
    EC_KEY *ec = keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    unsigned char *pub_key = NULL;
    int ok = 1;

    if (ec == NULL)
        return 0;

    /*
     * In this implementation, we can export/import only keydata in the
     * following combinations:
     *   - domain parameters only
     *   - public key with associated domain parameters (+optional other params)
     *   - private key with associated public key and domain parameters
     *         (+optional other params)
     *
     * This means:
     *   - domain parameters must always be requested
     *   - private key must be requested alongside public key
     *   - other parameters must be requested only alongside a key
     */
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
            && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0
            && (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && domparams_to_params(ec, tmpl, NULL);

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private =
            selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

        ok = ok && key_to_params(ec, tmpl, NULL, include_private, &pub_key);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
        ok = ok && otherparams_to_params(ec, tmpl, NULL);

    if (ok && (params = OSSL_PARAM_BLD_to_param(tmpl)) != NULL)
        ok = param_cb(params, cbarg);

    OSSL_PARAM_BLD_free_params(params);
    OSSL_PARAM_BLD_free(tmpl);
    OPENSSL_free(pub_key);
    return ok;
}

/* IMEXPORT = IMPORT + EXPORT */

# define EC_IMEXPORTABLE_DOM_PARAMETERS                          \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_NAME, NULL, 0)
# define EC_IMEXPORTABLE_PUBLIC_KEY                              \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0)
# define EC_IMEXPORTABLE_PRIVATE_KEY                             \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)
# define EC_IMEXPORTABLE_OTHER_PARAMETERS                        \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL)

/*
 * Include all the possible combinations of OSSL_PARAM arrays for
 * ec_imexport_types().
 *
 * They are in a separate file as it is ~100 lines of unreadable and
 * uninteresting machine generated stuff.
 *
 * TODO(3.0): the generated list looks quite ugly, as to cover all possible
 * combinations of the bits in `selection`, it also includes combinations that
 * are not really useful: we might want to consider alternatives to this
 * solution.
 */
#include "ec_kmgmt_imexport.inc"

static ossl_inline
const OSSL_PARAM *ec_imexport_types(int selection)
{
    int type_select = 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        type_select += 1;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        type_select += 2;
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        type_select += 4;
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
        type_select += 8;
    return ec_types[type_select];
}

static
const OSSL_PARAM *ec_import_types(int selection)
{
    return ec_imexport_types(selection);
}

static
const OSSL_PARAM *ec_export_types(int selection)
{
    return ec_imexport_types(selection);
}

static
int ec_get_params(void *key, OSSL_PARAM params[])
{
    int ret;
    EC_KEY *eck = key;
    const EC_GROUP *ecg = NULL;
    OSSL_PARAM *p;
    unsigned char *pub_key = NULL;

    ecg = EC_KEY_get0_group(eck);
    if (ecg == NULL)
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, ECDSA_size(eck)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, EC_GROUP_order_bits(ecg)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL) {
        int ecbits, sec_bits;

        ecbits = EC_GROUP_order_bits(ecg);

        /*
         * The following estimates are based on the values published
         * in Table 2 of "NIST Special Publication 800-57 Part 1 Revision 4"
         * at http://dx.doi.org/10.6028/NIST.SP.800-57pt1r4 .
         *
         * Note that the above reference explicitly categorizes algorithms in a
         * discrete set of values {80, 112, 128, 192, 256}, and that it is
         * relevant only for NIST approved Elliptic Curves, while OpenSSL
         * applies the same logic also to other curves.
         *
         * Classifications produced by other standardazing bodies might differ,
         * so the results provided for "bits of security" by this provider are
         * to be considered merely indicative, and it is the users'
         * responsibility to compare these values against the normative
         * references that may be relevant for their intent and purposes.
         */
        if (ecbits >= 512)
            sec_bits = 256;
        else if (ecbits >= 384)
            sec_bits = 192;
        else if (ecbits >= 256)
            sec_bits = 128;
        else if (ecbits >= 224)
            sec_bits = 112;
        else if (ecbits >= 160)
            sec_bits = 80;
        else
            sec_bits = ecbits / 2;

        if (!OSSL_PARAM_set_int(p, sec_bits))
            return 0;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) != NULL
        && !OSSL_PARAM_set_utf8_string(p, EC_DEFAULT_MD))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH);
    if (p != NULL) {
        int ecdh_cofactor_mode = 0;

        ecdh_cofactor_mode =
            (EC_KEY_get_flags(eck) & EC_FLAG_COFACTOR_ECDH) ? 1 : 0;

        if (!OSSL_PARAM_set_int(p, ecdh_cofactor_mode))
            return 0;
    }
    ret = domparams_to_params(eck, NULL, params)
          && key_to_params(eck, NULL, params, 1, &pub_key)
          && otherparams_to_params(eck, NULL, params);
    OPENSSL_free(pub_key);
    return ret;
}

static const OSSL_PARAM ec_known_gettable_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    EC_IMEXPORTABLE_DOM_PARAMETERS,
    EC_IMEXPORTABLE_PUBLIC_KEY,
    EC_IMEXPORTABLE_PRIVATE_KEY,
    EC_IMEXPORTABLE_OTHER_PARAMETERS,
    OSSL_PARAM_END
};

static
const OSSL_PARAM *ec_gettable_params(void)
{
    return ec_known_gettable_params;
}

static const OSSL_PARAM ec_known_settable_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
    OSSL_PARAM_END
};

static
const OSSL_PARAM *ec_settable_params(void)
{
    return ec_known_settable_params;
}

static
int ec_set_params(void *key, const OSSL_PARAM params[])
{
    EC_KEY *eck = key;

    return ec_key_otherparams_fromdata(eck, params);
}

static
int ec_validate(void *keydata, int selection)
{
    EC_KEY *eck = keydata;
    int ok = 0;
    BN_CTX *ctx = BN_CTX_new_ex(ec_key_get_libctx(eck));

    if (ctx == NULL)
        return 0;

    if ((selection & EC_POSSIBLE_SELECTIONS) != 0)
        ok = 1;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && EC_GROUP_check(EC_KEY_get0_group(eck), ctx);

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && ec_key_public_check(eck, ctx);

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && ec_key_private_check(eck);

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR)
        ok = ok && ec_key_pairwise_check(eck, ctx);

    BN_CTX_free(ctx);
    return ok;
}

struct ec_gen_ctx {
    OPENSSL_CTX *libctx;
    EC_GROUP *gen_group;
    int selection;
    int ecdh_mode;
};

static void *ec_gen_init(void *provctx, int selection)
{
    OPENSSL_CTX *libctx = PROV_LIBRARY_CONTEXT_OF(provctx);
    struct ec_gen_ctx *gctx = NULL;

    if ((selection & (EC_POSSIBLE_SELECTIONS)) == 0)
        return NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->libctx = libctx;
        gctx->gen_group = NULL;
        gctx->selection = selection;
        gctx->ecdh_mode = 0;
    }
    return gctx;
}

static int ec_gen_set_group(void *genctx, int nid)
{
    struct ec_gen_ctx *gctx = genctx;
    EC_GROUP *group;

    group = EC_GROUP_new_by_curve_name_ex(gctx->libctx, nid);
    if (group == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
        return 0;
    }
    EC_GROUP_free(gctx->gen_group);
    gctx->gen_group = group;
    return 1;
}
static int ec_gen_set_template(void *genctx, void *templ)
{
    struct ec_gen_ctx *gctx = genctx;
    EC_KEY *ec = templ;
    const EC_GROUP *ec_group;

    if (gctx == NULL || ec == NULL)
        return 0;
    if ((ec_group = EC_KEY_get0_group(ec)) == NULL)
        return 0;
    return ec_gen_set_group(gctx, EC_GROUP_get_curve_name(ec_group));
}

static int ec_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct ec_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH))
        != NULL) {
        if (!OSSL_PARAM_get_int(p, &gctx->ecdh_mode))
            return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_NAME))
        != NULL) {
        const char *curve_name = NULL;
        int ret = 0;

        switch (p->data_type) {
        case OSSL_PARAM_UTF8_STRING:
            /* The OSSL_PARAM functions have no support for this */
            curve_name = p->data;
            ret = (curve_name != NULL);
            break;
        case OSSL_PARAM_UTF8_PTR:
            ret = OSSL_PARAM_get_utf8_ptr(p, &curve_name);
            break;
        }

        if (ret) {
            int nid = ec_curve_name2nid(curve_name);

            if (nid == NID_undef) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
                ret = 0;
            } else {
                ret = ec_gen_set_group(gctx, nid);
            }
        }
        return ret;
    }
    return 1;
}

static const OSSL_PARAM *ec_gen_settable_params(void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_NAME, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
        OSSL_PARAM_END
    };

    return settable;
}

static int ec_gen_assign_group(EC_KEY *ec, EC_GROUP *group)
{
    if (group == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
        return 0;
    }
    return EC_KEY_set_group(ec, group) > 0;
}

/*
 * The callback arguments (osslcb & cbarg) are not used by EC_KEY generation
 */
static void *ec_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct ec_gen_ctx *gctx = genctx;
    EC_KEY *ec = NULL;
    int ret = 1;                 /* Start optimistically */

    if (gctx == NULL
        || (ec = EC_KEY_new_ex(gctx->libctx)) == NULL)
        return NULL;

    /* We must always assign a group, no matter what */
    ret = ec_gen_assign_group(ec, gctx->gen_group);
    /* Whether you want it or not, you get a keypair, not just one half */
    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ret = ret && EC_KEY_generate_key(ec);

    if (gctx->ecdh_mode != -1)
        ret = ret && ec_set_ecdh_cofactor_mode(ec, gctx->ecdh_mode);

    if (ret)
        return ec;

    /* Something went wrong, throw the key away */
    EC_KEY_free(ec);
    return NULL;
}

static void ec_gen_cleanup(void *genctx)
{
    struct ec_gen_ctx *gctx = genctx;

    if (gctx == NULL)
        return;

    EC_GROUP_free(gctx->gen_group);
    OPENSSL_free(gctx);
}

const OSSL_DISPATCH ec_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ec_newdata },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))ec_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
      (void (*)(void))ec_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))ec_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))ec_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))ec_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))ec_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ec_freedata },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))ec_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))ec_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))ec_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))ec_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ec_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))ec_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))ec_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ec_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))ec_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ec_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))ec_export_types },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))ec_query_operation_name },
    { 0, NULL }
};
