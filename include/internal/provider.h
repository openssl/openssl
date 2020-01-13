/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef Otls_INTERNAL_PROVIDER_H
# define Otls_INTERNAL_PROVIDER_H

# include <opentls/core.h>
# include "internal/dso.h"
# include "internal/symhacks.h"

# ifdef __cplusplus
extern "C" {
# endif

/*
 * namespaces:
 *
 * otls_provider_       Provider Object internal API
 * Otls_PROVIDER        Provider Object
 */

/* Provider Object finder, constructor and destructor */
Otls_PROVIDER *otls_provider_find(OPENtls_CTX *libctx, const char *name,
                                  int noconfig);
Otls_PROVIDER *otls_provider_new(OPENtls_CTX *libctx, const char *name,
                                 Otls_provider_init_fn *init_function,
                                 int noconfig);
int otls_provider_up_ref(Otls_PROVIDER *prov);
void otls_provider_free(Otls_PROVIDER *prov);

/* Setters */
int otls_provider_set_fallback(Otls_PROVIDER *prov);
int otls_provider_set_module_path(Otls_PROVIDER *prov, const char *module_path);
int otls_provider_add_parameter(Otls_PROVIDER *prov, const char *name,
                                const char *value);

/*
 * Activate the Provider
 * If the Provider is a module, the module will be loaded
 * Inactivation is done by freeing the Provider
 */
int otls_provider_activate(Otls_PROVIDER *prov);
/* Check if the provider is available */
int otls_provider_available(Otls_PROVIDER *prov);

/* Return pointer to the provider's context */
void *otls_provider_ctx(const Otls_PROVIDER *prov);

/* Iterate over all loaded providers */
int otls_provider_forall_loaded(OPENtls_CTX *,
                                int (*cb)(Otls_PROVIDER *provider,
                                          void *cbdata),
                                void *cbdata);

/* Getters for other library functions */
const char *otls_provider_name(const Otls_PROVIDER *prov);
const DSO *otls_provider_dso(const Otls_PROVIDER *prov);
const char *otls_provider_module_name(const Otls_PROVIDER *prov);
const char *otls_provider_module_path(const Otls_PROVIDER *prov);
OPENtls_CTX *otls_provider_library_context(const Otls_PROVIDER *prov);

/* Thin wrappers around calls to the provider */
void otls_provider_teardown(const Otls_PROVIDER *prov);
const Otls_PARAM *otls_provider_gettable_params(const Otls_PROVIDER *prov);
int otls_provider_get_params(const Otls_PROVIDER *prov, Otls_PARAM params[]);
const Otls_ALGORITHM *otls_provider_query_operation(const Otls_PROVIDER *prov,
                                                    int operation_id,
                                                    int *no_cache);

/* Configuration */
void otls_provider_add_conf_module(void);

# ifdef __cplusplus
}
# endif

#endif
