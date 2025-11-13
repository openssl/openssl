/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_PROV_CIPHERCOMMON_ASCON_H
# define OSSL_PROV_CIPHERCOMMON_ASCON_H

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>

/* Return value constants */
# define OSSL_RV_SUCCESS 1
# define OSSL_RV_ERROR 0

/* Common definitions */
/*
 * Note: FIXED_TAG_LENGTH is now defined in cipher_ascon128.h to avoid
 * including LibAscon header in common header
 */
#ifndef FIXED_TAG_LENGTH
# define FIXED_TAG_LENGTH 16  /* ASCON-128 uses 16-byte (128-bit) tag */
#endif

/*********************************************************************
 *
 *  Provider Context
 *
 *****/

struct provider_ctx_st
{
    const OSSL_CORE_HANDLE *core_handle;
};

void provider_ctx_free(struct provider_ctx_st *ctx);
struct provider_ctx_st *provider_ctx_new(const OSSL_CORE_HANDLE *core,
                                         const OSSL_DISPATCH *in);

#endif /* OSSL_PROV_CIPHERCOMMON_ASCON_H */
