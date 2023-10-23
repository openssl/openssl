/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/provider.h>
#include <openssl/core_dispatch.h>

const OSSL_CORE_HANDLE *FIPS_get_core_handle(OSSL_LIB_CTX *ctx);

int ossl_cipher_capable_aes_cbc_hmac_sha1(void);
int ossl_cipher_capable_aes_cbc_hmac_sha256(void);

OSSL_FUNC_provider_get_capabilities_fn ossl_prov_get_capabilities;

/* Set the error state if this is a FIPS module */
void ossl_set_error_state(const char *type);

/* Return true if the module is in a usable condition */
int ossl_prov_is_running(void);

uint64_t ossl_prov_get_avail_threads(OSSL_LIB_CTX *libctx);
void *ossl_prov_thread_start(OSSL_LIB_CTX *ctx,
                             OSSL_thread_start_handler_fn start,
                             void *data);
int ossl_prov_thread_join(void *task, uint32_t *ret);
int ossl_prov_thread_clean(void *vhandle);
