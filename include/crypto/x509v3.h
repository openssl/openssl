/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#ifndef OSSL_CRYPTO_X509V3_H
# define OSSL_CRYPTO_X509V3_H

#define EXT_UTF8STRING(nid) { nid, 0, ASN1_ITEM_ref(ASN1_UTF8STRING), \
                        0,0,0,0, \
                        (X509V3_EXT_I2S)i2s_ASN1_UTF8STRING, \
                        (X509V3_EXT_S2I)s2i_ASN1_UTF8STRING, \
                        0,0,0,0, \
                        NULL}

char *i2s_ASN1_UTF8STRING(X509V3_EXT_METHOD *method, ASN1_UTF8STRING *utf8);
ASN1_UTF8STRING *s2i_ASN1_UTF8STRING(X509V3_EXT_METHOD *method,
                                   X509V3_CTX *ctx, const char *str);

#endif
