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

static void evp_pkey_free_it(EVP_PKEY *key);

#ifndef FIPS_MODE

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
     * Only check that type match this early when both keys are legacy.
     * If either of them is provided, we let evp_keymgmt_util_copy()
     * do this check, after having exported either of them that isn't
     * provided.
     */
    if (to->keymgmt == NULL && from->keymgmt == NULL) {
        if (to->type == EVP_PKEY_NONE) {
            if (EVP_PKEY_set_type(to, from->type) == 0)
                return 0;
        } else if (to->type != from->type) {
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

    /*
     * If |from| is provided, we upgrade |to| to be provided as well.
     * This drops the legacy key from |to|.
     * evp_pkey_upgrade_to_provider() checks if |to| is already provided,
     * we don't need to do that here.
     *
     * TODO(3.0) We should investigate if that's too aggressive and make
     * this scenario unsupported instead.
     */
    if (from->keymgmt != NULL) {
        EVP_KEYMGMT *tmp_keymgmt = from->keymgmt;

        /*
         * The returned pointer is known to be cached, so we don't have to
         * save it.  However, if it's NULL, something went wrong and we can't
         * copy.
         */
        if (evp_pkey_upgrade_to_provider(to, NULL,
                                         &tmp_keymgmt, NULL) == NULL) {
            ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    /* For purely provided keys, we just call the keymgmt utility */
    if (to->keymgmt != NULL && from->keymgmt != NULL)
        return evp_keymgmt_util_copy(to, (EVP_PKEY *)from,
                                     OSSL_KEYMGMT_SELECT_ALL_PARAMETERS);

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

        if (from_keydata == NULL) {
            ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        return evp_keymgmt_copy(to->keymgmt, to->keydata, from_keydata,
                                OSSL_KEYMGMT_SELECT_ALL_PARAMETERS);
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
            return !evp_keymgmt_util_has((EVP_PKEY *)pkey,
                                         OSSL_KEYMGMT_SELECT_ALL_PARAMETERS);
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
     * Here, we know that we have a mixture of legacy and provided keys.
     * Try cross export and compare the resulting key data.
     */
    keymgmt1 = a->keymgmt;
    keydata1 = a->keydata;
    keymgmt2 = b->keymgmt;
    keydata2 = b->keydata;

    if ((keymgmt1 == NULL
         && !EVP_KEYMGMT_is_a(keymgmt2, OBJ_nid2sn(a->type)))
        || (keymgmt2 == NULL
            && !EVP_KEYMGMT_is_a(keymgmt1, OBJ_nid2sn(b->type))))
        return -1;               /* not the same key type */

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
        return evp_pkey_cmp_any(a, b, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS);

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
        return evp_pkey_cmp_any(a, b,
                                OSSL_KEYMGMT_SELECT_ALL_PARAMETERS
                                | OSSL_KEYMGMT_SELECT_PUBLIC_KEY);

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


/*
 * Setup a public key ASN1 method and ENGINE from a NID or a string. If pkey
 * is NULL just return 1 or 0 if the algorithm exists.
 */

static int pkey_set_type(EVP_PKEY *pkey, ENGINE *e, int type, const char *str,
                         int len)
{
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE **eptr = (e == NULL) ? &e :  NULL;

    if (pkey) {
        if (pkey->pkey.ptr)
            evp_pkey_free_it(pkey);
        /*
         * If key type matches and a method exists then this lookup has
         * succeeded once so just indicate success.
         */
        if ((type == pkey->save_type) && pkey->ameth)
            return 1;
# ifndef OPENSSL_NO_ENGINE
        /* If we have ENGINEs release them */
        ENGINE_finish(pkey->engine);
        pkey->engine = NULL;
        ENGINE_finish(pkey->pmeth_engine);
        pkey->pmeth_engine = NULL;
# endif
    }
    if (str)
        ameth = EVP_PKEY_asn1_find_str(eptr, str, len);
    else
        ameth = EVP_PKEY_asn1_find(eptr, type);
# ifndef OPENSSL_NO_ENGINE
    if (pkey == NULL && eptr != NULL)
        ENGINE_finish(e);
# endif
    if (ameth == NULL) {
        EVPerr(EVP_F_PKEY_SET_TYPE, EVP_R_UNSUPPORTED_ALGORITHM);
        return 0;
    }
    if (pkey) {
        pkey->ameth = ameth;
        pkey->engine = e;

        pkey->type = pkey->ameth->pkey_id;
        pkey->save_type = type;
    }
    return 1;
}

EVP_PKEY *EVP_PKEY_new_raw_private_key(int type, ENGINE *e,
                                       const unsigned char *priv,
                                       size_t len)
{
    EVP_PKEY *ret = EVP_PKEY_new();

    if (ret == NULL
            || !pkey_set_type(ret, e, type, NULL, -1)) {
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
            || !pkey_set_type(ret, e, type, NULL, -1)) {
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
            || !pkey_set_type(ret, e, EVP_PKEY_CMAC, NULL, -1)) {
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
    return pkey_set_type(pkey, NULL, type, NULL, -1);
}

int EVP_PKEY_set_type_str(EVP_PKEY *pkey, const char *str, int len)
{
    return pkey_set_type(pkey, NULL, EVP_PKEY_NONE, str, len);
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
        x->ameth = NULL;
    }
# ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(x->engine);
    x->engine = NULL;
    ENGINE_finish(x->pmeth_engine);
    x->pmeth_engine = NULL;
# endif
    x->type = x->save_type = EVP_PKEY_NONE;
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
    if (pkey != NULL) {
        if (pkey->ameth == NULL)
            return pkey->cache.size;
        else if (pkey->ameth->pkey_size != NULL)
            return pkey->ameth->pkey_size(pkey);
    }
    return 0;
}

void *evp_pkey_export_to_provider(EVP_PKEY *pk, OPENSSL_CTX *libctx,
                                  EVP_KEYMGMT **keymgmt,
                                  const char *propquery)
{
    EVP_KEYMGMT *allocated_keymgmt = NULL;
    EVP_KEYMGMT *tmp_keymgmt = NULL;
    void *keydata = NULL;

    if (pk == NULL)
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

    /* If no keymgmt was given or found, get a default keymgmt */
    if (tmp_keymgmt == NULL) {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pk, propquery);

        if (ctx != NULL && ctx->keytype != NULL)
            tmp_keymgmt = allocated_keymgmt =
                EVP_KEYMGMT_fetch(ctx->libctx, ctx->keytype, propquery);
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
/*
 * This differs from exporting in that it releases the legacy key and assigns
 * the export keymgmt and keydata to the "origin" provider side key instead
 * of the operation cache.
 */
void *evp_pkey_upgrade_to_provider(EVP_PKEY *pk, OPENSSL_CTX *libctx,
                                   EVP_KEYMGMT **keymgmt,
                                   const char *propquery)
{
    EVP_KEYMGMT *allocated_keymgmt = NULL;
    EVP_KEYMGMT *tmp_keymgmt = NULL;
    void *keydata = NULL;

    if (pk == NULL)
        return NULL;

    /*
     * If this key is already "upgraded", this function shouldn't have been
     * called.
     */
    if (!ossl_assert(pk->keymgmt == NULL))
        return NULL;

    if (keymgmt != NULL) {
        tmp_keymgmt = *keymgmt;
        *keymgmt = NULL;
    }

    /* If the key isn't a legacy one, bail out, but with proper values */
    if (pk->pkey.ptr == NULL) {
        tmp_keymgmt = pk->keymgmt;
        keydata = pk->keydata;
    } else {
        /* If the legacy key doesn't have an export function, give up */
        if (pk->ameth->export_to == NULL)
            return NULL;

        /* If no keymgmt was given, get a default keymgmt */
        if (tmp_keymgmt == NULL) {
            EVP_PKEY_CTX *ctx =
                EVP_PKEY_CTX_new_from_pkey(libctx, pk, propquery);

            if (ctx != NULL && ctx->keytype != NULL)
                tmp_keymgmt = allocated_keymgmt =
                    EVP_KEYMGMT_fetch(ctx->libctx, ctx->keytype, propquery);
            EVP_PKEY_CTX_free(ctx);
        }

        /* If we still don't have a keymgmt, give up */
        if (tmp_keymgmt == NULL)
            goto end;

        /* Make sure that the keymgmt key type matches the legacy NID */
        if (!ossl_assert(EVP_KEYMGMT_is_a(tmp_keymgmt, OBJ_nid2sn(pk->type))))
            goto end;

        if ((keydata = evp_keymgmt_newdata(tmp_keymgmt)) == NULL)
            goto end;

        if (!pk->ameth->export_to(pk, keydata, tmp_keymgmt)
            || !EVP_KEYMGMT_up_ref(tmp_keymgmt)) {
            evp_keymgmt_freedata(tmp_keymgmt, keydata);
            keydata = NULL;
            goto end;
        }

        /*
         * Clear the operation cache, all the legacy data, as well as the
         * dirty counters
         */
        evp_pkey_free_legacy(pk);
        pk->dirty_cnt_copy = 0;

        evp_keymgmt_util_clear_operation_cache(pk);
        pk->keymgmt = tmp_keymgmt;
        pk->keydata = keydata;
        evp_keymgmt_util_cache_keyinfo(pk);
    }

 end:
    /*
     * If nothing was upgraded, |tmp_keymgmt| might point at a freed
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
#endif  /* FIPS_MODE */
