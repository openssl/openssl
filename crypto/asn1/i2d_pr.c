/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <limits.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"

int i2d_PrivateKey(const EVP_PKEY *a, unsigned char **pp)
{
    if (a->ameth && a->ameth->old_priv_encode) {
        return a->ameth->old_priv_encode(a, pp);
    }
    if (a->ameth && a->ameth->priv_encode) {
        PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(a);
        int ret = 0;
        if (p8 != NULL) {
            ret = i2d_PKCS8_PRIV_KEY_INFO(p8, pp);
            PKCS8_PRIV_KEY_INFO_free(p8);
        }
        return ret;
    }
    if (evp_pkey_is_provided(a)) {
        /* |*pp| is unbounded, so we need an upper limit */
        size_t length = INT_MAX;
        /* The private key includes everything */
        int selection =
            OSSL_KEYMGMT_SELECT_ALL_PARAMETERS | OSSL_KEYMGMT_SELECT_KEYPAIR;
        int ret = -1;
        OSSL_ENCODER_CTX *ctx;

        if ((ctx = OSSL_ENCODER_CTX_new_by_EVP_PKEY(a, "DER", selection,
                                                    NULL, NULL)) != NULL
            && OSSL_ENCODER_CTX_get_num_encoders(ctx) != 0
            && OSSL_ENCODER_to_data(ctx, pp, &length))
            ret = (int)length;
        OSSL_ENCODER_CTX_free(ctx);
        return ret;
    }
    ASN1err(ASN1_F_I2D_PRIVATEKEY, ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
    return -1;
}
