/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include "crypto/ecx.h"
#include "prov/bio.h"             /* ossl_prov_bio_printf() */
#include "prov/implementations.h" /* ecx_keymgmt_functions */
#include "serializer_local.h"

void ecx_get_new_free_import(ECX_KEY_TYPE type,
                             OSSL_OP_keymgmt_new_fn **ecx_new,
                             OSSL_OP_keymgmt_free_fn **ecx_free,
                             OSSL_OP_keymgmt_import_fn **ecx_import)
{
    if (type == ECX_KEY_TYPE_X25519) {
        *ecx_new = ossl_prov_get_keymgmt_new(x25519_keymgmt_functions);
        *ecx_free = ossl_prov_get_keymgmt_free(x25519_keymgmt_functions);
        *ecx_import = ossl_prov_get_keymgmt_import(x25519_keymgmt_functions);
    } else if (type == ECX_KEY_TYPE_X448) {
        *ecx_new = ossl_prov_get_keymgmt_new(x448_keymgmt_functions);
        *ecx_free = ossl_prov_get_keymgmt_free(x448_keymgmt_functions);
        *ecx_import = ossl_prov_get_keymgmt_import(x448_keymgmt_functions);
    } else if (type == ECX_KEY_TYPE_ED25519) {
        *ecx_new = ossl_prov_get_keymgmt_new(ed25519_keymgmt_functions);
        *ecx_free = ossl_prov_get_keymgmt_free(ed25519_keymgmt_functions);
        *ecx_import = ossl_prov_get_keymgmt_import(ed25519_keymgmt_functions);
    } else if (type == ECX_KEY_TYPE_ED448) {
        *ecx_new = ossl_prov_get_keymgmt_new(ed448_keymgmt_functions);
        *ecx_free = ossl_prov_get_keymgmt_free(ed448_keymgmt_functions);
        *ecx_import = ossl_prov_get_keymgmt_import(ed448_keymgmt_functions);
    } else {
        *ecx_new = NULL;
        *ecx_free = NULL;
        *ecx_import = NULL;
    }
}


int ossl_prov_print_ecx(BIO *out, ECX_KEY *ecxkey, enum ecx_print_type type)
{
    const char *type_label = NULL;

    switch (type) {
    case ecx_print_priv:
        switch (ecxkey->type) {
        case ECX_KEY_TYPE_X25519:
            type_label = "X25519 Private-Key";
            break;
        case ECX_KEY_TYPE_X448:
            type_label = "X448 Private-Key";
            break;
        case ECX_KEY_TYPE_ED25519:
            type_label = "ED25519 Private-Key";
            break;
        case ECX_KEY_TYPE_ED448:
            type_label = "ED448 Private-Key";
            break;
        }
        break;
    case ecx_print_pub:
        switch (ecxkey->type) {
        case ECX_KEY_TYPE_X25519:
            type_label = "X25519 Public-Key";
            break;
        case ECX_KEY_TYPE_X448:
            type_label = "X448 Public-Key";
            break;
        case ECX_KEY_TYPE_ED25519:
            type_label = "ED25519 Public-Key";
            break;
        case ECX_KEY_TYPE_ED448:
            type_label = "ED448 Public-Key";
            break;
        }
        break;
    }

    if (type == ecx_print_priv && ecxkey->privkey == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (BIO_printf(out, "%s:\n", type_label) <= 0)
        return 0;
    if (type == ecx_print_priv
            && !ossl_prov_print_labeled_buf(out, "priv:", ecxkey->privkey,
                                            ecxkey->keylen))
        return 0;
    if (!ossl_prov_print_labeled_buf(out, "pub:", ecxkey->pubkey,
                                     ecxkey->keylen))
        return 0;

    return 1;
}


int ossl_prov_ecx_pub_to_der(const void *vecxkey, unsigned char **pder)
{
    const ECX_KEY *ecxkey = vecxkey;
    unsigned char *keyblob;

    if (ecxkey == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    keyblob = OPENSSL_memdup(ecxkey->pubkey, ecxkey->keylen);
    if (keyblob == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    *pder = keyblob;
    return ecxkey->keylen;
}

int ossl_prov_ecx_priv_to_der(const void *vecxkey, unsigned char **pder)
{
    const ECX_KEY *ecxkey = vecxkey;
    ASN1_OCTET_STRING oct;
    int keybloblen;

    if (ecxkey == NULL || ecxkey->privkey == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    oct.data = ecxkey->privkey;
    oct.length = ecxkey->keylen;
    oct.flags = 0;

    keybloblen = i2d_ASN1_OCTET_STRING(&oct, pder);
    if (keybloblen < 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    return keybloblen;
}
