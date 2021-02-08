/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>         /* For i2d_RSAPublicKey */
#include <openssl/dsa.h>         /* For i2d_DSAPublicKey */
#include <openssl/ec.h>          /* For i2o_ECPublicKey */
#include "crypto/asn1.h"
#include "crypto/evp.h"

static int i2d_provided(const EVP_PKEY *a, int selection,
                        const char *output_structures[],
                        unsigned char **pp)
{
    OSSL_ENCODER_CTX *ctx = NULL;
    int ret;

    for (ret = -1;
         ret == -1 && *output_structures != NULL;
         output_structures++) {
        /*
         * The i2d_ calls don't take a boundary length for *pp.  However,
         * OSSL_ENCODER_CTX_get_num_encoders() needs one, so we make one
         * up.
         */
        size_t len = INT_MAX;

        ctx = OSSL_ENCODER_CTX_new_by_EVP_PKEY(a, selection, "DER",
                                               *output_structures, NULL);
        if (ctx == NULL)
            return -1;
        if (OSSL_ENCODER_to_data(ctx, pp, &len))
            ret = (int)len;
        OSSL_ENCODER_CTX_free(ctx);
        ctx = NULL;
    }

    if (ret == -1)
        ERR_raise(ERR_LIB_ASN1, ASN1_R_UNSUPPORTED_TYPE);
    return ret;
}

int i2d_KeyParams(const EVP_PKEY *a, unsigned char **pp)
{
    if (evp_pkey_is_provided(a)) {
        const char *output_structures[] = { "type-specific", NULL };

        return i2d_provided(a, EVP_PKEY_KEY_PARAMETERS, output_structures, pp);
    }
    if (a->ameth != NULL && a->ameth->param_encode != NULL)
        return a->ameth->param_encode(a, pp);
    ERR_raise(ERR_LIB_ASN1, ASN1_R_UNSUPPORTED_TYPE);
    return -1;
}

int i2d_KeyParams_bio(BIO *bp, const EVP_PKEY *pkey)
{
    return ASN1_i2d_bio_of(EVP_PKEY, i2d_KeyParams, bp, pkey);
}

int i2d_PrivateKey(const EVP_PKEY *a, unsigned char **pp)
{
    if (evp_pkey_is_provided(a)) {
        const char *output_structures[] = { "type-specific", "pkcs8", NULL };

        return i2d_provided(a, EVP_PKEY_KEYPAIR, output_structures, pp);
    }
    if (a->ameth != NULL && a->ameth->old_priv_encode != NULL) {
        return a->ameth->old_priv_encode(a, pp);
    }
    if (a->ameth != NULL && a->ameth->priv_encode != NULL) {
        PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(a);
        int ret = 0;

        if (p8 != NULL) {
            ret = i2d_PKCS8_PRIV_KEY_INFO(p8, pp);
            PKCS8_PRIV_KEY_INFO_free(p8);
        }
        return ret;
    }
    ERR_raise(ERR_LIB_ASN1, ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
    return -1;
}

int i2d_PublicKey(const EVP_PKEY *a, unsigned char **pp)
{
    if (evp_pkey_is_provided(a)) {
        const char *output_structures[] = { "type-specific", NULL };

        return i2d_provided(a, EVP_PKEY_PUBLIC_KEY, output_structures, pp);
    }
    switch (EVP_PKEY_id(a)) {
    case EVP_PKEY_RSA:
        return i2d_RSAPublicKey(EVP_PKEY_get0_RSA(a), pp);
#ifndef OPENSSL_NO_DSA
    case EVP_PKEY_DSA:
        return i2d_DSAPublicKey(EVP_PKEY_get0_DSA(a), pp);
#endif
#ifndef OPENSSL_NO_EC
    case EVP_PKEY_EC:
        return i2o_ECPublicKey(EVP_PKEY_get0_EC_KEY(a), pp);
#endif
    default:
        ERR_raise(ERR_LIB_ASN1, ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
        return -1;
    }
}
