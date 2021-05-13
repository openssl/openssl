/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <crypto/x509_acert.h>

#ifndef OSSL_CRYPTO_X509_X509_ACERT_H
# define OSSL_CRYPTO_X509_X509_ACERT_H

# define X509_ACERT_ISSUER_V1 0
# define X509_ACERT_ISSUER_V2 1

DECLARE_ASN1_ITEM(X509_HOLDER)
DECLARE_ASN1_FUNCTIONS(OSSL_ISSUER_SERIAL)
DECLARE_ASN1_ITEM(X509_ACERT_ISSUER)
DECLARE_ASN1_FUNCTIONS(X509_ACERT_ISSUER_V2FORM)
#endif
