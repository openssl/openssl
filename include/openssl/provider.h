/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_PROVIDER_H
# define OSSL_PROVIDER_H

# include <openssl/core.h>

# ifdef __cplusplus
extern "C" {
# endif

/* Load and unload a provider */
OSSL_PROVIDER *OSSL_load_provider(OPENSSL_CTX *, const char *name);
int OSSL_unload_provider(OSSL_PROVIDER *prov);

const OSSL_ITEM *OSSL_get_provider_param_types(OSSL_PROVIDER *prov);
int OSSL_get_provider_params(OSSL_PROVIDER *prov, const OSSL_PARAM params[]);

/* Add a provider, for built in providers */
int OSSL_add_provider(OPENSSL_CTX *,
                      const char *name, ossl_provider_init_fn *init_fn);

# ifdef __cplusplus
}
# endif

#endif
