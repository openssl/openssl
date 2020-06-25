/*
 * Copyright 2019-2020=-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* MAC stuff */

#ifndef OPENSSL_EVP_MAC_H
# define OPENSSL_EVP_MAC_H
# pragma once

# include <openssl/opensslconf.h>
# include <openssl/types.h>
# include <openssl/core.h>

# ifdef __cplusplus
extern "C" {
# endif

EVP_MAC *EVP_MAC_fetch(OPENSSL_CTX *libctx, const char *algorithm,
                       const char *properties);
int EVP_MAC_up_ref(EVP_MAC *mac);
void EVP_MAC_free(EVP_MAC *mac);
int EVP_MAC_number(const EVP_MAC *mac);
int EVP_MAC_is_a(const EVP_MAC *mac, const char *name);
const OSSL_PROVIDER *EVP_MAC_provider(const EVP_MAC *mac);
int EVP_MAC_get_params(EVP_MAC *mac, OSSL_PARAM params[]);

EVP_MAC_CTX *EVP_MAC_new_ctx(EVP_MAC *mac);
void EVP_MAC_free_ctx(EVP_MAC_CTX *ctx);
EVP_MAC_CTX *EVP_MAC_dup_ctx(const EVP_MAC_CTX *src);
EVP_MAC *EVP_MAC_get_ctx_mac(EVP_MAC_CTX *ctx);
int EVP_MAC_get_ctx_params(EVP_MAC_CTX *ctx, OSSL_PARAM params[]);
int EVP_MAC_set_ctx_params(EVP_MAC_CTX *ctx, const OSSL_PARAM params[]);

size_t EVP_MAC_size(EVP_MAC_CTX *ctx);
int EVP_MAC_init(EVP_MAC_CTX *ctx);
int EVP_MAC_update(EVP_MAC_CTX *ctx, const unsigned char *data, size_t datalen);
int EVP_MAC_final(EVP_MAC_CTX *ctx,
                  unsigned char *out, size_t *outl, size_t outsize);
const OSSL_PARAM *EVP_MAC_gettable_params(const EVP_MAC *mac);
const OSSL_PARAM *EVP_MAC_gettable_ctx_params(const EVP_MAC *mac);
const OSSL_PARAM *EVP_MAC_settable_ctx_params(const EVP_MAC *mac);

void EVP_MAC_do_all_provided(OPENSSL_CTX *libctx,
                             void (*fn)(EVP_MAC *mac, void *arg),
                             void *arg);
void EVP_MAC_names_do_all(const EVP_MAC *mac,
                          void (*fn)(const char *name, void *data),
                          void *data);

# ifdef __cplusplus
}
# endif
#endif /* OPENSSL_EVP_MAC_H */
