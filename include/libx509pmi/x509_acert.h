/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(LIBX509PMI_X509_ACERT_H)
#define LIBX509PMI_X509_ACERT_H

/*
 * The libx509pmi entry point for the attribute certificate API.  The
 * declarations are shared with <openssl/x509_acert.h>, but code entering
 * through this header gets every public symbol renamed to its
 * libx509pmi-native LIBX509PMI_* name and must be linked against
 * libx509pmi.
 */

#if (defined(OPENSSL_X509_ACERT_H) || defined(OPENSSL_X509V3_H)) \
    && !defined(OSSL_LIBX509PMI_NAMES)
#error "<openssl/x509_acert.h> or <openssl/x509v3.h> was included before <libx509pmi/x509_acert.h>"
#endif /* (defined(OPENSSL_X509_ACERT_H) || defined(OPENSSL_X509V3_H)) && !defined(OSSL_LIBX509PMI_NAMES) */

#if !defined(OSSL_LIBX509PMI_NAMES)
#define OSSL_LIBX509PMI_NAMES
#endif /* !defined(OSSL_LIBX509PMI_NAMES) */

#include <libx509pmi/names.h>
#include <openssl/x509_acert.h>

#endif /* !defined(LIBX509PMI_X509_ACERT_H) */
