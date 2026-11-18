/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(LIBCMS_PKCS7_H)
#define LIBCMS_PKCS7_H

/*
 * The libcms entry point for the PKCS7 API.  The declarations are shared
 * with <openssl/pkcs7.h>, but code entering through this header gets every
 * public symbol renamed to its libcms-native LIBCMS_* name and must be
 * linked against libcms.
 */

#if defined(OPENSSL_PKCS7_H) && !defined(OSSL_LIBCMS_NAMES)
#error "<openssl/pkcs7.h> was included before <libcms/pkcs7.h>"
#endif /* defined(OPENSSL_PKCS7_H) && !defined(OSSL_LIBCMS_NAMES) */

/*
 * OSSL_LIBCMS_NAMES also tells <openssl/pkcs7.h> that the declarations are
 * being reached through libcms, where the API is not deprecated.
 */
#if !defined(OSSL_LIBCMS_NAMES)
#define OSSL_LIBCMS_NAMES
#endif /* !defined(OSSL_LIBCMS_NAMES) */

#include <libcms/names.h>
#include <openssl/pkcs7.h>

#endif /* !defined(LIBCMS_PKCS7_H) */
