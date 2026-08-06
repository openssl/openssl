/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef LIBCMP_CRMF_H
#define LIBCMP_CRMF_H

/*
 * The libcmp entry point for the CRMF API.  The declarations are shared
 * with <openssl/crmf.h>, but code entering through this header gets every
 * public symbol renamed to its libcmp-native OSSL_LIBCRMF_* name and must
 * be linked against libcmp.
 */

#if defined(OPENSSL_CRMF_H) && !defined(OSSL_LIBCMP_NAMES)
#error "<openssl/crmf.h> was included before <libcmp/crmf.h>"
#endif

#ifndef OSSL_LIBCMP_NAMES
#define OSSL_LIBCMP_NAMES
#endif
#include <libcmp/names.h>
#include <openssl/crmf.h>

#endif /* LIBCMP_CRMF_H */
