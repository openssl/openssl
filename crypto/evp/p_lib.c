/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * DSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <stdio.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/cmac.h>
#include <openssl/engine.h>
#include <openssl/params.h>
#include <openssl/serializer.h>
#include <openssl/core_names.h>

#include "crypto/asn1.h"
#include "crypto/evp.h"
#include "internal/provider.h"
#include "evp_local.h"

static int pkey_set_type(EVP_PKEY *pkey, ENGINE *e, int type, const char *str,
                         int len, EVP_KEYMGMT *keymgmt);
static void evp_pkey_free_it(EVP_PKEY *key);

#ifndef FIPS_MODE

/* The type of parameters selected in key parameter functions */
# define SELECT_PARAMETERS OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS

int EVP_PKEY_bits(const EVP_PKEY *pkey)
{
    if (pkey != NULL) {
        if (pkey->ameth == NULL)
            return pkey->cache.bits;
        else if (pkey->ameth->pkey_bits)
            return pkey->ameth->pkey_bits(pkey);
    }
    return 0;
}

int EVP_PKEY_security_bits(const EVP_PKEY *pkey)
{
    if (pkey == NULL)
        return 0;
    if (pkey->ameth == NULL)
        return pkey->cache.security_bits;
    if (pkey->ameth->pkey_security_bits == NULL)
        return -2;
    return pkey->ameth->pkey_security_bits(pkey);
}

int EVP_PKEY_save_parameters(EVP_PKEY *pkey, int mode)
{
# ifndef OPENSSL_NO_DSA
    if (pkey->type == EVP_PKEY_DSA) {
        int ret = pkey->save_parameters;

        if (mode >= 0)
            pkey->save_parameters = mode;
        return ret;
    }
# endif
# ifndef OPENSSL_NO_EC
    if (pkey->type == EVP_PKEY_EC) {
        int ret = pkey->save_parameters;

        if (mode >= 0)
            pkey->save_parameters = mode;
        return ret;
    }
# endif
    return 0;
}

int EVP_PKEY_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from)
{
    /*
     * TODO: clean up legacy stuff from this function when legacy support
     * is gone.
     */

    /*
     * If |to| is a legacy key and |from| isn't, we must downgrade |from|.
     * If that fails, this function fails.
     */
    if (to->type != EVP_PKEY_NONE && from->keymgmt != NULL)
        if (!evp_pkey_downgrade((EVP_PKEY *)from))
            return 0;

    /*
     * Make sure |to| is typed.  Content is less important at this early
     * stage.
     *
     * 1.  If |to| is untyped, assign |from|'s key type to it.
     * 2.  If |to| contains a legacy key, compare its |type| to |from|'s.
     *     (|from| was already downgraded above)
     *
     * If |to| is a provided key, there's nothing more to do here, functions
     * like evp_keymgmt_util_copy() and evp_pkey_export_to_provider() called
     * further down help us find out if they are the same or not.
     */
    if (to->type == EVP_PKEY_NONE && to->keymgmt == NULL) {
        if (from->type != EVP_PKEY_NONE) {
            if (EVP_PKEY_set_type(to, from->type) == 0)
                return 0;
        } else {
            if (EVP_PKEY_set_type_by_keymgmt(to, from->keymgmt) == 0)
                return 0;
        }
    } else if (to->type != EVP_PKEY_NONE) {
        if (to->type != from->type) {
            EVPerr(EVP_F_EVP_PKEY_COPY_PARAMETERS, EVP_R_DIFFERENT_KEY_TYPES);
            goto err;
        }
    }

    if (EVP_PKEY_missing_parameters(from)) {
        EVPerr(EVP_F_EVP_PKEY_COPY_PARAMETERS, EVP_R_MISSING_PARAMETERS);
        goto err;
    }

    if (!EVP_PKEY_missing_parameters(to)) {
        if (EVP_PKEY_cmp_parameters(to, from) == 1)
            return 1;
        EVPerr(EVP_F_EVP_PKEY_COPY_PARAMETERS, EVP_R_DIFFERENT_PARAMETERS);
        return 0;
    }

    /* For purely provided keys, we just call the keymgmt utility */
    if (to->keymgmt != NULL && from->keymgmt != NULL)
        return evp_keymgmt_util_copy(to, (EVP_PKEY *)from, SELECT_PARAMETERS);

    /*
     * If |to| is provided, we know that |from| is legacy at this point.
     * Try exporting |from| to |to|'s keymgmt, then use evp_keymgmt_copy()
     * to copy the appropriate data to |to|'s keydata.
     */
    if (to->keymgmt != NULL) {
        EVP_KEYMGMT *to_keymgmt = to->keymgmt;
        void *from_keydata =
            evp_pkey_export_to_provider((EVP_PKEY *)from, NULL, &to_keymgmt,
                                        NULL);

        /*
         * If we get a NULL, it could be an internal error, or it could be
         * that there's a key mismatch.  We're pretending the latter...
         */
        if (from_keydata == NULL) {
            ERR_raise(ERR_LIB_EVP, EVP_R_DIFFERENT_KEY_TYPES);
            return 0;
        }
        return evp_keymgmt_copy(to->keymgmt, to->keydata, from_keydata,
                                SELECT_PARAMETERS);
    }

    /* Both keys are legacy */
    if (from->ameth != NULL && from->ameth->param_copy != NULL)
        return from->ameth->param_copy(to, from);
 err:
    return 0;
}

int EVP_PKEY_missing_parameters(const EVP_PKEY *pkey)
{
    if (pkey != NULL) {
        if (pkey->keymgmt != NULL)
            return !evp_keymgmt_util_has((EVP_PKEY *)pkey, SELECT_PARAMETERS);
        else if (pkey->ameth != NULL && pkey->ameth->param_missing != NULL)
            return pkey->ameth->param_missing(pkey);
    }
    return 0;
}

/*
 * This function is called for any mixture of keys except pure legacy pair.
 * TODO When legacy keys are gone, we replace a call to this functions with
 * a call to evp_keymgmt_util_match().
 */
static int evp_pkey_cmp_any(const EVP_PKEY *a, const EVP_PKEY *b,
                            int selection)
{
    EVP_KEYMGMT *keymgmt1 = NULL, *keymgmt2 = NULL;
    void *keydata1 = NULL, *keydata2 = NULL, *tmp_keydata = NULL;

    /* If none of them are provided, this function shouldn't have been called */
    if (!ossl_assert(a->keymgmt != NULL || b->keymgmt != NULL))
        return -2;

    /* For purely provided keys, we just call the keymgmt utility */
    if (a->keymgmt != NULL && b->keymgmt != NULL)
        return evp_keymgmt_util_match((EVP_PKEY *)a, (EVP_PKEY *)b, selection);

    /*
     * At this point, one of them is provided, the other not.  This allows
     * us to compare types using legacy NIDs.
     */
    if ((a->type != EVP_PKEY_NONE
         && !EVP_KEYMGMT_is_a(b->keymgmt, OBJ_nid2sn(a->type)))
        || (b->type != EVP_PKEY_NONE
            && !EVP_KEYMGMT_is_a(a->keymgmt, OBJ_nid2sn(b->type))))
        return -1;               /* not the same key type */

    /*
     * We've determined that they both are the same keytype, so the next
     * step is to do a bit of cross export to ensure we have keydata for
     * both keys in the same keymgmt.
     */
    keymgmt1 = a->keymgmt;
    keydata1 = a->keydata;
    keymgmt2 = b->keymgmt;
    keydata2 = b->keydata;

    if (keymgmt2 != NULL && keymgmt2->match != NULL) {
        tmp_keydata =
            evp_pkey_export_to_provider((EVP_PKEY *)a, NULL, &keymgmt2, NULL);
        if (tmp_keydata != NULL) {
            keymgmt1 = keymgmt2;
            keydata1 = tmp_keydata;
        }
    }
    if (tmp_keydata == NULL && keymgmt1 != NULL && keymgmt1->match != NULL) {
        tmp_keydata =
            evp_pkey_export_to_provider((EVP_PKEY *)b, NULL, &keymgmt1, NULL);
        if (tmp_keydata != NULL) {
            keymgmt2 = keymgmt1;
            keydata2 = tmp_keydata;
        }
    }

    /* If we still don't have matching keymgmt implementations, we give up */
    if (keymgmt1 != keymgmt2)
        return -2;

    return evp_keymgmt_match(keymgmt1, keydata1, keydata2, selection);
}

int EVP_PKEY_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)
{
    /*
     * TODO: clean up legacy stuff from this function when legacy support
     * is gone.
     */

    if (a->keymgmt != NULL || b->keymgmt != NULL)
        return evp_pkey_cmp_any(a, b, SELECT_PARAMETERS);

    /* All legacy keys */
    if (a->type != b->type)
        return -1;
    if (a->ameth != NULL && a->ameth->param_cmp != NULL)
        return a->ameth->param_cmp(a, b);
    return -2;
}

int EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    /*
     * TODO: clean up legacy stuff from this function when legacy support
     * is gone.
     */

    if (a->keymgmt != NULL || b->keymgmt != NULL)
        return evp_pkey_cmp_any(a, b, (SELECT_PARAMETERS
                                       | OSSL_KEYMGMT_SELECT_PUBLIC_KEY));

    /* All legacy keys */
    if (a->type != b->type)
        return -1;

    if (a->ameth != NULL) {
        int ret;
        /* Compare parameters if the algorithm has them */
        if (a->ameth->param_cmp != NULL) {
            ret = a->ameth->param_cmp(a, b);
            if (ret <= 0)
                return ret;
        }

        if (a->ameth->pub_cmp != NULL)
            return a->ameth->pub_cmp(a, b);
    }

    return -2;
}

EVP_PKEY *EVP_PKEY_new_raw_private_key(int type, ENGINE *e,
                                       const unsigned char *priv,
                                       size_t len)
{
    EVP_PKEY *ret = EVP_PKEY_new();

    if (ret == NULL
        || !pkey_set_type(ret, e, type, NULL, -1, NULL)) {
        /* EVPerr already called */
        goto err;
    }

    if (ret->ameth->set_priv_key == NULL) {
        EVPerr(EVP_F_EVP_PKEY_NEW_RAW_PRIVATE_KEY,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        goto err;
    }

    if (!ret->ameth->set_priv_key(ret, priv, len)) {
        EVPerr(EVP_F_EVP_PKEY_NEW_RAW_PRIVATE_KEY, EVP_R_KEY_SETUP_FAILED);
        goto err;
    }

    return ret;

 err:
    EVP_PKEY_free(ret);
    return NULL;
}

EVP_PKEY *EVP_PKEY_new_raw_public_key(int type, ENGINE *e,
                                      const unsigned char *pub,
                                      size_t len)
{
    EVP_PKEY *ret = EVP_PKEY_new();

    if (ret == NULL
        || !pkey_set_type(ret, e, type, NULL, -1, NULL)) {
        /* EVPerr already called */
        goto err;
    }

    if (ret->ameth->set_pub_key == NULL) {
        EVPerr(EVP_F_EVP_PKEY_NEW_RAW_PUBLIC_KEY,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        goto err;
    }

    if (!ret->ameth->set_pub_key(ret, pub, len)) {
        EVPerr(EVP_F_EVP_PKEY_NEW_RAW_PUBLIC_KEY, EVP_R_KEY_SETUP_FAILED);
        goto err;
    }

    return ret;

 err:
    EVP_PKEY_free(ret);
    return NULL;
}

int EVP_PKEY_get_raw_private_key(const EVP_PKEY *pkey, unsigned char *priv,
                                 size_t *len)
{
    /* TODO(3.0) Do we need to do anything about provider side keys? */
     if (pkey->ameth->get_priv_key == NULL) {
        EVPerr(EVP_F_EVP_PKEY_GET_RAW_PRIVATE_KEY,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return 0;
    }

    if (!pkey->ameth->get_priv_key(pkey, priv, len)) {
        EVPerr(EVP_F_EVP_PKEY_GET_RAW_PRIVATE_KEY, EVP_R_GET_RAW_KEY_FAILED);
        return 0;
    }

    return 1;
}

int EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey, unsigned char *pub,
                                size_t *len)
{
    /* TODO(3.0) Do we need to do anything about provider side keys? */
     if (pkey->ameth->get_pub_key == NULL) {
        EVPerr(EVP_F_EVP_PKEY_GET_RAW_PUBLIC_KEY,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return 0;
    }

    if (!pkey->ameth->get_pub_key(pkey, pub, len)) {
        EVPerr(EVP_F_EVP_PKEY_GET_RAW_PUBLIC_KEY, EVP_R_GET_RAW_KEY_FAILED);
        return 0;
    }

    return 1;
}

EVP_PKEY *EVP_PKEY_new_CMAC_key(ENGINE *e, const unsigned char *priv,
                                size_t len, const EVP_CIPHER *cipher)
{
# ifndef OPENSSL_NO_CMAC
#  ifndef OPENSSL_NO_ENGINE
    const char *engine_id = e != NULL ? ENGINE_get_id(e) : NULL;
#  endif
    const char *cipher_name = EVP_CIPHER_name(cipher);
    const OSSL_PROVIDER *prov = EVP_CIPHER_provider(cipher);
    OPENSSL_CTX *libctx =
        prov == NULL ? NULL : ossl_provider_library_context(prov);
    EVP_PKEY *ret = EVP_PKEY_new();
    EVP_MAC *cmac = EVP_MAC_fetch(libctx, OSSL_MAC_NAME_CMAC, NULL);
    EVP_MAC_CTX *cmctx = cmac != NULL ? EVP_MAC_CTX_new(cmac) : NULL;
    OSSL_PARAM params[4];
    size_t paramsn = 0;

    if (ret == NULL
        || cmctx == NULL
        || !pkey_set_type(ret, e, EVP_PKEY_CMAC, NULL, -1, NULL)) {
        /* EVPerr already called */
        goto err;
    }

#  ifndef OPENSSL_NO_ENGINE
    if (engine_id != NULL)
        params[paramsn++] =
            OSSL_PARAM_construct_utf8_string("engine", (char *)engine_id, 0);
#  endif

    params[paramsn++] =
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                         (char *)cipher_name, 0);
    params[paramsn++] =
        OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
                                          (char *)priv, len);
    params[paramsn] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_CTX_set_params(cmctx, params)) {
        EVPerr(EVP_F_EVP_PKEY_NEW_CMAC_KEY, EVP_R_KEY_SETUP_FAILED);
        goto err;
    }

    ret->pkey.ptr = cmctx;
    return ret;

 err:
    EVP_PKEY_free(ret);
    EVP_MAC_CTX_free(cmctx);
    EVP_MAC_free(cmac);
    return NULL;
# else
    EVPerr(EVP_F_EVP_PKEY_NEW_CMAC_KEY,
           EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
    return NULL;
# endif
}

int EVP_PKEY_set_type(EVP_PKEY *pkey, int type)
{
    return pkey_set_type(pkey, NULL, type, NULL, -1, NULL);
}

int EVP_PKEY_set_type_str(EVP_PKEY *pkey, const char *str, int len)
{
    return pkey_set_type(pkey, NULL, EVP_PKEY_NONE, str, len, NULL);
}

int EVP_PKEY_set_alias_type(EVP_PKEY *pkey, int type)
{
    if (pkey->type == type) {
        return 1; /* it already is that type */
    }

    /*
     * The application is requesting to alias this to a different pkey type,
     * but not one that resolves to the base type.
     */
    if (EVP_PKEY_type(type) != EVP_PKEY_base_id(pkey)) {
        EVPerr(EVP_F_EVP_PKEY_SET_ALIAS_TYPE, EVP_R_UNSUPPORTED_ALGORITHM);
        return 0;
    }

    pkey->type = type;
    return 1;
}

# ifndef OPENSSL_NO_ENGINE
int EVP_PKEY_set1_engine(EVP_PKEY *pkey, ENGINE *e)
{
    if (e != NULL) {
        if (!ENGINE_init(e)) {
            EVPerr(EVP_F_EVP_PKEY_SET1_ENGINE, ERR_R_ENGINE_LIB);
            return 0;
        }
        if (ENGINE_get_pkey_meth(e, pkey->type) == NULL) {
            ENGINE_finish(e);
            EVPerr(EVP_F_EVP_PKEY_SET1_ENGINE, EVP_R_UNSUPPORTED_ALGORITHM);
            return 0;
        }
    }
    ENGINE_finish(pkey->pmeth_engine);
    pkey->pmeth_engine = e;
    return 1;
}

ENGINE *EVP_PKEY_get0_engine(const EVP_PKEY *pkey)
{
    return pkey->engine;
}
# endif
int EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key)
{
    int alias = type;

#ifndef OPENSSL_NO_EC
    if (EVP_PKEY_type(type) == EVP_PKEY_EC) {
        const EC_GROUP *group = EC_KEY_get0_group(key);

        if (group != NULL && EC_GROUP_get_curve_name(group) == NID_sm2)
            alias = EVP_PKEY_SM2;
    }
#endif

    if (pkey == NULL || !EVP_PKEY_set_type(pkey, type))
        return 0;
    if (!EVP_PKEY_set_alias_type(pkey, alias))
        return 0;
    pkey->pkey.ptr = key;
    return (key != NULL);
}

void *EVP_PKEY_get0(const EVP_PKEY *pkey)
{
    if (!evp_pkey_downgrade((EVP_PKEY *)pkey)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_INACCESSIBLE_KEY);
        return NULL;
    }
    return pkey->pkey.ptr;
}

const unsigned char *EVP_PKEY_get0_hmac(const EVP_PKEY *pkey, size_t *len)
{
    ASN1_OCTET_STRING *os = NULL;
    if (pkey->type != EVP_PKEY_HMAC) {
        EVPerr(EVP_F_EVP_PKEY_GET0_HMAC, EVP_R_EXPECTING_AN_HMAC_KEY);
        return NULL;
    }
    os = EVP_PKEY_get0(pkey);
    *len = os->length;
    return os->data;
}

# ifndef OPENSSL_NO_POLY1305
const unsigned char *EVP_PKEY_get0_poly1305(const EVP_PKEY *pkey, size_t *len)
{
    ASN1_OCTET_STRING *os = NULL;
    if (pkey->type != EVP_PKEY_POLY1305) {
        EVPerr(EVP_F_EVP_PKEY_GET0_POLY1305, EVP_R_EXPECTING_A_POLY1305_KEY);
        return NULL;
    }
    os = EVP_PKEY_get0(pkey);
    *len = os->length;
    return os->data;
}
# endif

# ifndef OPENSSL_NO_SIPHASH
const unsigned char *EVP_PKEY_get0_siphash(const EVP_PKEY *pkey, size_t *len)
{
    ASN1_OCTET_STRING *os = NULL;

    if (pkey->type != EVP_PKEY_SIPHASH) {
        EVPerr(EVP_F_EVP_PKEY_GET0_SIPHASH, EVP_R_EXPECTING_A_SIPHASH_KEY);
        return NULL;
    }
    os = EVP_PKEY_get0(pkey);
    *len = os->length;
    return os->data;
}
# endif

# ifndef OPENSSL_NO_RSA
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key)
{
    int ret = EVP_PKEY_assign_RSA(pkey, key);
    if (ret)
        RSA_up_ref(key);
    return ret;
}

RSA *EVP_PKEY_get0_RSA(const EVP_PKEY *pkey)
{
    if (!evp_pkey_downgrade((EVP_PKEY *)pkey)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_INACCESSIBLE_KEY);
        return NULL;
    }
    if (pkey->type != EVP_PKEY_RSA && pkey->type != EVP_PKEY_RSA_PSS) {
        EVPerr(EVP_F_EVP_PKEY_GET0_RSA, EVP_R_EXPECTING_AN_RSA_KEY);
        return NULL;
    }
    return pkey->pkey.rsa;
}

RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey)
{
    RSA *ret = EVP_PKEY_get0_RSA(pkey);
    if (ret != NULL)
        RSA_up_ref(ret);
    return ret;
}
# endif

# ifndef OPENSSL_NO_DSA
int EVP_PKEY_set1_DSA(EVP_PKEY *pkey, DSA *key)
{
    int ret = EVP_PKEY_assign_DSA(pkey, key);
    if (ret)
        DSA_up_ref(key);
    return ret;
}

DSA *EVP_PKEY_get0_DSA(const EVP_PKEY *pkey)
{
    if (!evp_pkey_downgrade((EVP_PKEY *)pkey)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_INACCESSIBLE_KEY);
        return NULL;
    }
    if (pkey->type != EVP_PKEY_DSA) {
        EVPerr(EVP_F_EVP_PKEY_GET0_DSA, EVP_R_EXPECTING_A_DSA_KEY);
        return NULL;
    }
    return pkey->pkey.dsa;
}

DSA *EVP_PKEY_get1_DSA(EVP_PKEY *pkey)
{
    DSA *ret = EVP_PKEY_get0_DSA(pkey);
    if (ret != NULL)
        DSA_up_ref(ret);
    return ret;
}
# endif

# ifndef OPENSSL_NO_EC

int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, EC_KEY *key)
{
    int ret = EVP_PKEY_assign_EC_KEY(pkey, key);
    if (ret)
        EC_KEY_up_ref(key);
    return ret;
}

EC_KEY *EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey)
{
    if (!evp_pkey_downgrade((EVP_PKEY *)pkey)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_INACCESSIBLE_KEY);
        return NULL;
    }
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        EVPerr(EVP_F_EVP_PKEY_GET0_EC_KEY, EVP_R_EXPECTING_A_EC_KEY);
        return NULL;
    }
    return pkey->pkey.ec;
}

EC_KEY *EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey)
{
    EC_KEY *ret = EVP_PKEY_get0_EC_KEY(pkey);
    if (ret != NULL)
        EC_KEY_up_ref(ret);
    return ret;
}
# endif

# ifndef OPENSSL_NO_DH

int EVP_PKEY_set1_DH(EVP_PKEY *pkey, DH *key)
{
    int type = DH_get0_q(key) == NULL ? EVP_PKEY_DH : EVP_PKEY_DHX;
    int ret = EVP_PKEY_assign(pkey, type, key);

    if (ret)
        DH_up_ref(key);
    return ret;
}

DH *EVP_PKEY_get0_DH(const EVP_PKEY *pkey)
{
    if (!evp_pkey_downgrade((EVP_PKEY *)pkey)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_INACCESSIBLE_KEY);
        return NULL;
    }
    if (pkey->type != EVP_PKEY_DH && pkey->type != EVP_PKEY_DHX) {
        EVPerr(EVP_F_EVP_PKEY_GET0_DH, EVP_R_EXPECTING_A_DH_KEY);
        return NULL;
    }
    return pkey->pkey.dh;
}

DH *EVP_PKEY_get1_DH(EVP_PKEY *pkey)
{
    DH *ret = EVP_PKEY_get0_DH(pkey);
    if (ret != NULL)
        DH_up_ref(ret);
    return ret;
}
# endif

int EVP_PKEY_type(int type)
{
    int ret;
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *e;
    ameth = EVP_PKEY_asn1_find(&e, type);
    if (ameth)
        ret = ameth->pkey_id;
    else
        ret = NID_undef;
# ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(e);
# endif
    return ret;
}

int EVP_PKEY_id(const EVP_PKEY *pkey)
{
    return pkey->type;
}

int EVP_PKEY_base_id(const EVP_PKEY *pkey)
{
    return EVP_PKEY_type(pkey->type);
}


static int print_reset_indent(BIO **out, int pop_f_prefix, long saved_indent)
{
    BIO_set_indent(*out, saved_indent);
    if (pop_f_prefix) {
        BIO *next = BIO_pop(*out);

        BIO_free(*out);
        *out = next;
    }
    return 1;
}

static int print_set_indent(BIO **out, int *pop_f_prefix, long *saved_indent,
                            long indent)
{
    *pop_f_prefix = 0;
    *saved_indent = 0;
    if (indent > 0) {
        long i = BIO_get_indent(*out);

        *saved_indent =  (i < 0 ? 0 : i);
        if (BIO_set_indent(*out, indent) <= 0) {
            if ((*out = BIO_push(BIO_new(BIO_f_prefix()), *out)) == NULL)
                return 0;
            *pop_f_prefix = 1;
        }
        if (BIO_set_indent(*out, indent) <= 0) {
            print_reset_indent(out, *pop_f_prefix, *saved_indent);
            return 0;
        }
    }
    return 1;
}

static int unsup_alg(BIO *out, const EVP_PKEY *pkey, int indent,
                     const char *kstr)
{
    return BIO_indent(out, indent, 128)
        && BIO_printf(out, "%s algorithm \"%s\" unsupported\n",
                      kstr, OBJ_nid2ln(pkey->type)) > 0;
}

static int print_pkey(const EVP_PKEY *pkey, BIO *out, int indent,
                      const char *propquery /* For provided serialization */,
                      int (*legacy_print)(BIO *out, const EVP_PKEY *pkey,
                                          int indent, ASN1_PCTX *pctx),
                      ASN1_PCTX *legacy_pctx /* For legacy print */)
{
    int pop_f_prefix;
    long saved_indent;
    OSSL_SERIALIZER_CTX *ctx = NULL;
    int ret = -2;                /* default to unsupported */

    if (!print_set_indent(&out, &pop_f_prefix, &saved_indent, indent))
        return 0;

    ctx = OSSL_SERIALIZER_CTX_new_by_EVP_PKEY(pkey, propquery);
    if (OSSL_SERIALIZER_CTX_get_serializer(ctx) != NULL)
        ret = OSSL_SERIALIZER_to_bio(ctx, out);
    OSSL_SERIALIZER_CTX_free(ctx);

    if (ret != -2)
        goto end;

    /* legacy fallback */
    if (legacy_print != NULL)
        ret = legacy_print(out, pkey, 0, legacy_pctx);
    else
        ret = unsup_alg(out, pkey, 0, "Public Key");

 end:
    print_reset_indent(&out, pop_f_prefix, saved_indent);
    return ret;
}

int EVP_PKEY_print_public(BIO *out, const EVP_PKEY *pkey,
                          int indent, ASN1_PCTX *pctx)
{
    return print_pkey(pkey, out, indent, OSSL_SERIALIZER_PUBKEY_TO_TEXT_PQ,
                      (pkey->ameth != NULL ? pkey->ameth->pub_print : NULL),
                      pctx);
}

int EVP_PKEY_print_private(BIO *out, const EVP_PKEY *pkey,
                           int indent, ASN1_PCTX *pctx)
{
    return print_pkey(pkey, out, indent, OSSL_SERIALIZER_PrivateKey_TO_TEXT_PQ,
                      (pkey->ameth != NULL ? pkey->ameth->priv_print : NULL),
                      pctx);
}

int EVP_PKEY_print_params(BIO *out, const EVP_PKEY *pkey,
                          int indent, ASN1_PCTX *pctx)
{
    return print_pkey(pkey, out, indent, OSSL_SERIALIZER_Parameters_TO_TEXT_PQ,
                      (pkey->ameth != NULL ? pkey->ameth->param_print : NULL),
                      pctx);
}

static int legacy_asn1_ctrl_to_param(EVP_PKEY *pkey, int op,
                                     int arg1, void *arg2)
{
    if (pkey->keymgmt == NULL)
        return 0;
    switch (op) {
    case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
        {
            char mdname[80] = "";
            int nid;
            int rv = EVP_PKEY_get_default_digest_name(pkey, mdname,
                                                      sizeof(mdname));

            if (rv <= 0)
                return rv;
            nid = OBJ_sn2nid(mdname);
            if (nid == NID_undef)
                nid = OBJ_ln2nid(mdname);
            if (nid == NID_undef)
                return 0;
            *(int *)arg2 = nid;
            return 1;
        }
    default:
        return -2;
    }
}

static int evp_pkey_asn1_ctrl(EVP_PKEY *pkey, int op, int arg1, void *arg2)
{
    if (pkey->ameth == NULL)
        return legacy_asn1_ctrl_to_param(pkey, op, arg1, arg2);
    if (pkey->ameth->pkey_ctrl == NULL)
        return -2;
    return pkey->ameth->pkey_ctrl(pkey, op, arg1, arg2);
}

int EVP_PKEY_get_default_digest_nid(EVP_PKEY *pkey, int *pnid)
{
    return evp_pkey_asn1_ctrl(pkey, ASN1_PKEY_CTRL_DEFAULT_MD_NID, 0, pnid);
}

int EVP_PKEY_get_default_digest_name(EVP_PKEY *pkey,
                                     char *mdname, size_t mdname_sz)
{
    if (pkey->ameth == NULL) {
        OSSL_PARAM params[3];
        char mddefault[100] = "";
        char mdmandatory[100] = "";

        params[0] =
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST,
                                             mddefault, sizeof(mddefault));
        params[1] =
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST,
                                             mdmandatory,
                                             sizeof(mdmandatory));
        params[2] = OSSL_PARAM_construct_end();
        if (!evp_keymgmt_get_params(pkey->keymgmt, pkey->keydata, params))
            return 0;
        if (mdmandatory[0] != '\0') {
            OPENSSL_strlcpy(mdname, mdmandatory, mdname_sz);
            return 2;
        }
        OPENSSL_strlcpy(mdname, mddefault, mdname_sz);
        return 1;
    }

    {
        int nid = NID_undef;
        int rv = EVP_PKEY_get_default_digest_nid(pkey, &nid);
        const char *name = rv > 0 ? OBJ_nid2sn(nid) : NULL;

        if (rv > 0)
            OPENSSL_strlcpy(mdname, name, mdname_sz);
        return rv;
    }
}

int EVP_PKEY_supports_digest_nid(EVP_PKEY *pkey, int nid)
{
    int rv, default_nid;

    rv = evp_pkey_asn1_ctrl(pkey, ASN1_PKEY_CTRL_SUPPORTS_MD_NID, nid, NULL);
    if (rv == -2) {
        /*
         * If there is a mandatory default digest and this isn't it, then
         * the answer is 'no'.
         */
        rv = EVP_PKEY_get_default_digest_nid(pkey, &default_nid);
        if (rv == 2)
            return (nid == default_nid);
        /* zero is an error from EVP_PKEY_get_default_digest_nid() */
        if (rv == 0)
            return -1;
    }
    return rv;
}

int EVP_PKEY_set1_tls_encodedpoint(EVP_PKEY *pkey,
                               const unsigned char *pt, size_t ptlen)
{
    if (ptlen > INT_MAX)
        return 0;
    if (evp_pkey_asn1_ctrl(pkey, ASN1_PKEY_CTRL_SET1_TLS_ENCPT, ptlen,
                           (void *)pt) <= 0)
        return 0;
    return 1;
}

size_t EVP_PKEY_get1_tls_encodedpoint(EVP_PKEY *pkey, unsigned char **ppt)
{
    int rv;
    rv = evp_pkey_asn1_ctrl(pkey, ASN1_PKEY_CTRL_GET1_TLS_ENCPT, 0, ppt);
    if (rv <= 0)
        return 0;
    return rv;
}

#endif /* FIPS_MODE */

/*- All methods below can also be used in FIPS_MODE */

EVP_PKEY *EVP_PKEY_new(void)
{
    EVP_PKEY *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        EVPerr(EVP_F_EVP_PKEY_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->type = EVP_PKEY_NONE;
    ret->save_type = EVP_PKEY_NONE;
    ret->references = 1;
    ret->save_parameters = 1;
    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        EVPerr(EVP_F_EVP_PKEY_NEW, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(ret);
        return NULL;
    }
    return ret;
}

/*
 * Setup a public key management method.
 *
 * For legacy keys, either |type| or |str| is expected to have the type
 * information.  In this case, the setup consists of finding an ASN1 method
 * and potentially an ENGINE, and setting those fields in |pkey|.
 *
 * For provider side keys, |keymgmt| is expected to be non-NULL.  In this
 * case, the setup consists of setting the |keymgmt| field in |pkey|.
 *
 * If pkey is NULL just return 1 or 0 if the key management method exists.
 */

static int pkey_set_type(EVP_PKEY *pkey, ENGINE *e, int type, const char *str,
                         int len, EVP_KEYMGMT *keymgmt)
{
#ifndef FIPS_MODE
    const EVP_PKEY_ASN1_METHOD *ameth = NULL;
    ENGINE **eptr = (e == NULL) ? &e :  NULL;
#endif

    /*
     * The setups can't set both legacy and provider side methods.
     * It is forbidden
     */
    if (!ossl_assert(type == EVP_PKEY_NONE || keymgmt == NULL)
        || !ossl_assert(e == NULL || keymgmt == NULL)) {
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (pkey != NULL) {
        int free_it = 0;

#ifndef FIPS_MODE
        free_it = free_it || pkey->pkey.ptr != NULL;
#endif
        free_it = free_it || pkey->keydata != NULL;
        if (free_it)
            evp_pkey_free_it(pkey);
#ifndef FIPS_MODE
        /*
         * If key type matches and a method exists then this lookup has
         * succeeded once so just indicate success.
         */
        if (pkey->type != EVP_PKEY_NONE
            && type == pkey->save_type
            && pkey->ameth != NULL)
            return 1;
# ifndef OPENSSL_NO_ENGINE
        /* If we have ENGINEs release them */
        ENGINE_finish(pkey->engine);
        pkey->engine = NULL;
        ENGINE_finish(pkey->pmeth_engine);
        pkey->pmeth_engine = NULL;
# endif
#endif
    }
#ifndef FIPS_MODE
    if (str != NULL)
        ameth = EVP_PKEY_asn1_find_str(eptr, str, len);
    else if (type != EVP_PKEY_NONE)
        ameth = EVP_PKEY_asn1_find(eptr, type);
# ifndef OPENSSL_NO_ENGINE
    if (pkey == NULL && eptr != NULL)
        ENGINE_finish(e);
# endif
#endif


    {
        int check = 1;

#ifndef FIPS_MODE
        check = check && ameth == NULL;
#endif
        check = check && keymgmt == NULL;
        if (check) {
            EVPerr(EVP_F_PKEY_SET_TYPE, EVP_R_UNSUPPORTED_ALGORITHM);
            return 0;
        }
    }
    if (pkey != NULL) {
        if (keymgmt != NULL && !EVP_KEYMGMT_up_ref(keymgmt)) {
            ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
            return 0;
        }

        pkey->keymgmt = keymgmt;

        pkey->save_type = type;
        pkey->type = type;

#ifndef FIPS_MODE
        /*
         * If the internal "origin" key is provider side, don't save |ameth|.
         * The main reason is that |ameth| is one factor to detect that the
         * internal "origin" key is a legacy one.
         */
        if (keymgmt == NULL)
            pkey->ameth = ameth;
        pkey->engine = e;

        /*
         * The EVP_PKEY_ASN1_METHOD |pkey_id| serves different purposes,
         * depending on if we're setting this key to contain a legacy or
         * a provider side "origin" key.  For a legacy key, we assign it
         * to the |type| field, but for a provider side key, we assign it
         * to the |save_type| field, because |type| is supposed to be set
         * to EVP_PKEY_NONE in that case.
         */
        if (keymgmt != NULL)
            pkey->save_type = ameth->pkey_id;
        else if (pkey->ameth != NULL)
            pkey->type = ameth->pkey_id;
#endif
    }
    return 1;
}

#ifndef FIPS_MODE
static void find_ameth(const char *name, void *data)
{
    const char **str = data;

    /*
     * The error messages from pkey_set_type() are uninteresting here,
     * and misleading.
     */
    ERR_set_mark();

    if (pkey_set_type(NULL, NULL, EVP_PKEY_NONE, name, strlen(name),
                      NULL)) {
        if (str[0] == NULL)
            str[0] = name;
        else if (str[1] == NULL)
            str[1] = name;
    }

    ERR_pop_to_mark();
}
#endif

int EVP_PKEY_set_type_by_keymgmt(EVP_PKEY *pkey, EVP_KEYMGMT *keymgmt)
{
#ifndef FIPS_MODE
# define EVP_PKEY_TYPE_STR str[0]
# define EVP_PKEY_TYPE_STRLEN (str[0] == NULL ? -1 : (int)strlen(str[0]))
    /*
     * Find at most two strings that have an associated EVP_PKEY_ASN1_METHOD
     * Ideally, only one should be found.  If two (or more) are found, the
     * match is ambiguous.  This should never happen, but...
     */
    const char *str[2] = { NULL, NULL };

    EVP_KEYMGMT_names_do_all(keymgmt, find_ameth, &str);
    if (str[1] != NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        return 0;
    }
#else
# define EVP_PKEY_TYPE_STR NULL
# define EVP_PKEY_TYPE_STRLEN -1
#endif
    return pkey_set_type(pkey, NULL, EVP_PKEY_NONE,
                         EVP_PKEY_TYPE_STR, EVP_PKEY_TYPE_STRLEN,
                         keymgmt);

#undef EVP_PKEY_TYPE_STR
#undef EVP_PKEY_TYPE_STRLEN
}

int EVP_PKEY_up_ref(EVP_PKEY *pkey)
{
    int i;

    if (CRYPTO_UP_REF(&pkey->references, &i, pkey->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("EVP_PKEY", pkey);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

#ifndef FIPS_MODE
void evp_pkey_free_legacy(EVP_PKEY *x)
{
    if (x->ameth != NULL) {
        if (x->ameth->pkey_free != NULL)
            x->ameth->pkey_free(x);
        x->pkey.ptr = NULL;
    }
# ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(x->engine);
    x->engine = NULL;
    ENGINE_finish(x->pmeth_engine);
    x->pmeth_engine = NULL;
# endif
    x->type = EVP_PKEY_NONE;
}
#endif  /* FIPS_MODE */

static void evp_pkey_free_it(EVP_PKEY *x)
{
    /* internal function; x is never NULL */

    evp_keymgmt_util_clear_operation_cache(x);
#ifndef FIPS_MODE
    evp_pkey_free_legacy(x);
#endif

    if (x->keymgmt != NULL) {
        evp_keymgmt_freedata(x->keymgmt, x->keydata);
        EVP_KEYMGMT_free(x->keymgmt);
        x->keymgmt = NULL;
        x->keydata = NULL;
    }
}

void EVP_PKEY_free(EVP_PKEY *x)
{
    int i;

    if (x == NULL)
        return;

    CRYPTO_DOWN_REF(&x->references, &i, x->lock);
    REF_PRINT_COUNT("EVP_PKEY", x);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);
    evp_pkey_free_it(x);
    CRYPTO_THREAD_lock_free(x->lock);
#ifndef FIPS_MODE
    sk_X509_ATTRIBUTE_pop_free(x->attributes, X509_ATTRIBUTE_free);
#endif
    OPENSSL_free(x);
}

int EVP_PKEY_size(const EVP_PKEY *pkey)
{
    int size = 0;

    if (pkey != NULL) {
        size = pkey->cache.size;
#ifndef FIPS_MODE
        if (pkey->ameth != NULL && pkey->ameth->pkey_size != NULL)
            size = pkey->ameth->pkey_size(pkey);
#endif
    }
    return size;
}

void *evp_pkey_export_to_provider(EVP_PKEY *pk, OPENSSL_CTX *libctx,
                                  EVP_KEYMGMT **keymgmt,
                                  const char *propquery)
{
    EVP_KEYMGMT *allocated_keymgmt = NULL;
    EVP_KEYMGMT *tmp_keymgmt = NULL;
    void *keydata = NULL;
    int check;

    if (pk == NULL)
        return NULL;

    /* No key data => nothing to export */
    check = 1;
#ifndef FIPS_MODE
    check = check && pk->pkey.ptr == NULL;
#endif
    check = check && pk->keydata == NULL;
    if (check)
        return NULL;

#ifndef FIPS_MODE
    if (pk->pkey.ptr != NULL) {
        /*
         * If the legacy key doesn't have an dirty counter or export function,
         * give up
         */
        if (pk->ameth->dirty_cnt == NULL || pk->ameth->export_to == NULL)
            return NULL;
    }
#endif

    if (keymgmt != NULL) {
        tmp_keymgmt = *keymgmt;
        *keymgmt = NULL;
    }

    /*
     * If no keymgmt was given or found, get a default keymgmt.  We do so by
     * letting EVP_PKEY_CTX_new_from_pkey() do it for us, then we steal it.
     */
    if (tmp_keymgmt == NULL) {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pk, propquery);

        tmp_keymgmt = ctx->keymgmt;
        ctx->keymgmt = NULL;
        EVP_PKEY_CTX_free(ctx);
    }

    /* If there's still no keymgmt to be had, give up */
    if (tmp_keymgmt == NULL)
        goto end;

#ifndef FIPS_MODE
    if (pk->pkey.ptr != NULL) {
        size_t i = 0;

        /*
         * If the legacy "origin" hasn't changed since last time, we try
         * to find our keymgmt in the operation cache.  If it has changed,
         * |i| remains zero, and we will clear the cache further down.
         */
        if (pk->ameth->dirty_cnt(pk) == pk->dirty_cnt_copy) {
            i = evp_keymgmt_util_find_operation_cache_index(pk, tmp_keymgmt);

            /*
             * If |tmp_keymgmt| is present in the operation cache, it means
             * that export doesn't need to be redone.  In that case, we take
             * token copies of the cached pointers, to have token success
             * values to return.
             */
            if (i < OSSL_NELEM(pk->operation_cache)
                && pk->operation_cache[i].keymgmt != NULL) {
                keydata = pk->operation_cache[i].keydata;
                goto end;
            }
        }

        /*
         * TODO(3.0) Right now, we assume we have ample space.  We will have
         * to think about a cache aging scheme, though, if |i| indexes outside
         * the array.
         */
        if (!ossl_assert(i < OSSL_NELEM(pk->operation_cache)))
            goto end;

        /* Make sure that the keymgmt key type matches the legacy NID */
        if (!ossl_assert(EVP_KEYMGMT_is_a(tmp_keymgmt, OBJ_nid2sn(pk->type))))
            goto end;

        if ((keydata = evp_keymgmt_newdata(tmp_keymgmt)) == NULL)
            goto end;

        if (!pk->ameth->export_to(pk, keydata, tmp_keymgmt)) {
            evp_keymgmt_freedata(tmp_keymgmt, keydata);
            keydata = NULL;
            goto end;
        }

        /*
         * If the dirty counter changed since last time, then clear the
         * operation cache.  In that case, we know that |i| is zero.  Just
         * in case this is a re-export, we increment then decrement the
         * keymgmt reference counter.
         */
        if (!EVP_KEYMGMT_up_ref(tmp_keymgmt)) { /* refcnt++ */
            evp_keymgmt_freedata(tmp_keymgmt, keydata);
            keydata = NULL;
            goto end;
        }
        if (pk->ameth->dirty_cnt(pk) != pk->dirty_cnt_copy)
            evp_keymgmt_util_clear_operation_cache(pk);
        EVP_KEYMGMT_free(tmp_keymgmt); /* refcnt-- */

        /* Add the new export to the operation cache */
        if (!evp_keymgmt_util_cache_keydata(pk, i, tmp_keymgmt, keydata)) {
            evp_keymgmt_freedata(tmp_keymgmt, keydata);
            keydata = NULL;
            goto end;
        }

        /* Synchronize the dirty count */
        pk->dirty_cnt_copy = pk->ameth->dirty_cnt(pk);
        goto end;
    }
#endif  /* FIPS_MODE */

    keydata = evp_keymgmt_util_export_to_provider(pk, tmp_keymgmt);

 end:
    /*
     * If nothing was exported, |tmp_keymgmt| might point at a freed
     * EVP_KEYMGMT, so we clear it to be safe.  It shouldn't be useful for
     * the caller either way in that case.
     */
    if (keydata == NULL)
        tmp_keymgmt = NULL;

    if (keymgmt != NULL)
        *keymgmt = tmp_keymgmt;

    EVP_KEYMGMT_free(allocated_keymgmt);
    return keydata;
}

#ifndef FIPS_MODE
int evp_pkey_downgrade(EVP_PKEY *pk)
{
    EVP_KEYMGMT *keymgmt = pk->keymgmt;
    void *keydata = pk->keydata;
    int type = pk->save_type;
    const char *keytype = NULL;

    /* If this isn't a provider side key, we're done */
    if (keymgmt == NULL)
        return 1;

    /* Get the key type name for error reporting */
    if (type != EVP_PKEY_NONE)
        keytype = OBJ_nid2sn(type);
    else
        keytype =
            evp_first_name(EVP_KEYMGMT_provider(keymgmt), keymgmt->name_id);

    /*
     * |save_type| was set when any of the EVP_PKEY_set_type functions
     * was called.  It was set to EVP_PKEY_NONE if the key type wasn't
     * recognised to be any of the legacy key types, and the downgrade
     * isn't possible.
     */
    if (type == EVP_PKEY_NONE) {
        ERR_raise_data(ERR_LIB_EVP, EVP_R_UNKNOWN_KEY_TYPE,
                       "key type = %s, can't downgrade", keytype);
        return 0;
    }

    /*
     * To be able to downgrade, we steal the provider side "origin" keymgmt
     * and keydata.  We've already grabbed the pointers, so all we need to
     * do is clear those pointers in |pk| and then call evp_pkey_free_it().
     * That way, we can restore |pk| if we need to.
     */
    pk->keymgmt = NULL;
    pk->keydata = NULL;
    evp_pkey_free_it(pk);
    if (EVP_PKEY_set_type(pk, type)) {
        /* If the key is typed but empty, we're done */
        if (keydata == NULL)
            return 1;

        if (pk->ameth->import_from == NULL) {
            ERR_raise_data(ERR_LIB_EVP, EVP_R_NO_IMPORT_FUNCTION,
                           "key type = %s", keytype);
        } else if (evp_keymgmt_export(keymgmt, keydata,
                                      OSSL_KEYMGMT_SELECT_ALL,
                                      pk->ameth->import_from, pk)) {
            /*
             * Save the provider side data in the operation cache, so they'll
             * find it again.  evp_pkey_free_it() cleared the cache, so it's
             * safe to assume slot zero is free.
             * Note that evp_keymgmt_util_cache_keydata() increments keymgmt's
             * reference count.
             */
            evp_keymgmt_util_cache_keydata(pk, 0, keymgmt, keydata);

            /* Synchronize the dirty count */
            pk->dirty_cnt_copy = pk->ameth->dirty_cnt(pk);
            return 1;
        }

        ERR_raise_data(ERR_LIB_EVP, EVP_R_KEYMGMT_EXPORT_FAILURE,
                       "key type = %s", keytype);
    }

    /*
     * Something went wrong.  This could for example happen if the keymgmt
     * turns out to be an HSM implementation that refuses to let go of some
     * of the key data, typically the private bits.  In this case, we restore
     * the provider side internal "origin" and leave it at that.
     */
    if (!ossl_assert(EVP_PKEY_set_type_by_keymgmt(pk, keymgmt))) {
        /* This should not be impossible */
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    pk->keydata = keydata;
    evp_keymgmt_util_cache_keyinfo(pk);
    return 0;     /* No downgrade, but at least the key is restored */
}
#endif  /* FIPS_MODE */
