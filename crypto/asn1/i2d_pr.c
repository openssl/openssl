/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
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
    if (a->keymgmt != NULL) {
        const char *encprop = OSSL_ENCODER_PrivateKey_TO_DER_PQ;
        OSSL_ENCODER_CTX *ctx =
            OSSL_ENCODER_CTX_new_by_EVP_PKEY(a, encprop);
        BIO *out = BIO_new(BIO_s_mem());
        BUF_MEM *buf = NULL;
        int ret = -1;

        if (ctx != NULL
            && out != NULL
            && OSSL_ENCODER_CTX_get_encoder(ctx) != NULL
            && OSSL_ENCODER_to_bio(ctx, out)
            && BIO_get_mem_ptr(out, &buf) > 0) {
            ret = buf->length;

            if (pp != NULL) {
                if (*pp == NULL) {
                    *pp = (unsigned char *)buf->data;
                    buf->length = 0;
                    buf->data = NULL;
                } else {
                    memcpy(*pp, buf->data, ret);
                    *pp += ret;
                }
            }
        }
        BIO_free(out);
        OSSL_ENCODER_CTX_free(ctx);
        return ret;
    }
    ASN1err(ASN1_F_I2D_PRIVATEKEY, ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
    return -1;
}
