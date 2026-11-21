/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(LIBX509PMI_X509V3_H)
#define LIBX509PMI_X509V3_H

/*
 * The libx509pmi entry point for the PMI part of the X.509v3 API.  The
 * declarations are shared with <openssl/x509v3.h>, but code entering
 * through this header gets every symbol libx509pmi provides renamed to its
 * libx509pmi-native LIBX509PMI_* name and must be linked against
 * libx509pmi.  The rest of <openssl/x509v3.h> is unaffected.
 */

#if defined(OPENSSL_X509V3_H) && !defined(OSSL_LIBX509PMI_NAMES)
#error "<openssl/x509v3.h> was included before <libx509pmi/x509v3.h>"
#endif /* defined(OPENSSL_X509V3_H) && !defined(OSSL_LIBX509PMI_NAMES) */

#if !defined(OSSL_LIBX509PMI_NAMES)
#define OSSL_LIBX509PMI_NAMES
#endif /* !defined(OSSL_LIBX509PMI_NAMES) */

#include <libx509pmi/names.h>
#include <openssl/x509v3.h>

#endif /* !defined(LIBX509PMI_X509V3_H) */
