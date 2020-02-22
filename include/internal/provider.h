/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_PROVIDER_H
# define OSSL_INTERNAL_PROVIDER_H

# include <openssl/core.h>
# include <openssl/core_numbers.h>
# include "internal/dso.h"
# include "internal/symhacks.h"

# ifdef __cplusplus
extern "C" {
# endif

/*
 * namespaces:
 *
 * ossl_provider_       Provider Object internal API
 * OSSL_PROVIDER        Provider Object
 */

/* Provider Object finder, constructor and destructor */
OSSL_PROVIDER *ossl_provider_find(OPENSSL_CTX *libctx, const char *name,
                                  int noconfig);
OSSL_PROVIDER *ossl_provider_new(OPENSSL_CTX *libctx, const char *name,
                                 OSSL_provider_init_fn *init_function,
                                 int noconfig);
int ossl_provider_up_ref(OSSL_PROVIDER *prov);
void ossl_provider_free(OSSL_PROVIDER *prov);

/* Setters */
int ossl_provider_set_fallback(OSSL_PROVIDER *prov);
int ossl_provider_set_module_path(OSSL_PROVIDER *prov, const char *module_path);
int ossl_provider_add_parameter(OSSL_PROVIDER *prov, const char *name,
                                const char *value);

/*
 * Activate the Provider
 * If the Provider is a module, the module will be loaded
 * Inactivation is done by freeing the Provider
 */
int ossl_provider_activate(OSSL_PROVIDER *prov);
/* Check if the provider is available */
int ossl_provider_available(OSSL_PROVIDER *prov);

/* Return pointer to the provider's context */
void *ossl_provider_ctx(const OSSL_PROVIDER *prov);

/* Iterate over all loaded providers */
int ossl_provider_forall_loaded(OPENSSL_CTX *,
                                int (*cb)(OSSL_PROVIDER *provider,
                                          void *cbdata),
                                void *cbdata);

/* Getters for other library functions */
const char *ossl_provider_name(const OSSL_PROVIDER *prov);
const DSO *ossl_provider_dso(const OSSL_PROVIDER *prov);
const char *ossl_provider_module_name(const OSSL_PROVIDER *prov);
const char *ossl_provider_module_path(const OSSL_PROVIDER *prov);
OPENSSL_CTX *ossl_provider_library_context(const OSSL_PROVIDER *prov);

/* Thin wrappers around calls to the provider */
void ossl_provider_teardown(const OSSL_PROVIDER *prov);
const OSSL_PARAM *ossl_provider_gettable_params(const OSSL_PROVIDER *prov);
int ossl_provider_get_params(const OSSL_PROVIDER *prov, OSSL_PARAM params[]);
const OSSL_ALGORITHM *ossl_provider_query_operation(const OSSL_PROVIDER *prov,
                                                    int operation_id,
                                                    int *no_cache);

/* Configuration */
void ossl_provider_add_conf_module(void);

# ifdef __cplusplus
}
# endif

#endif
