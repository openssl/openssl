/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(LIBCMS_CMS_H)
#define LIBCMS_CMS_H

/*
 * The libcms entry point for the CMS API.  The declarations are shared
 * with <openssl/cms.h>, but code entering through this header gets every
 * public symbol renamed to its libcms-native LIBCMS_* name and must be
 * linked against libcms.
 */

#if defined(OPENSSL_CMS_H) && !defined(OSSL_LIBCMS_NAMES)
#error "<openssl/cms.h> was included before <libcms/cms.h>"
#endif /* defined(OPENSSL_CMS_H) && !defined(OSSL_LIBCMS_NAMES) */

/*
 * OSSL_LIBCMS_NAMES also tells <openssl/cms.h> that the declarations are
 * being reached through libcms, where the API is not deprecated.
 */
#if !defined(OSSL_LIBCMS_NAMES)
#define OSSL_LIBCMS_NAMES
#endif /* !defined(OSSL_LIBCMS_NAMES) */

#include <libcms/names.h>
#include <openssl/cms.h>

#endif /* !defined(LIBCMS_CMS_H) */
