/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef OPENtls_PROVIDER_H
# define OPENtls_PROVIDER_H

# include <opentls/core.h>

# ifdef __cplusplus
extern "C" {
# endif

/* Load and unload a provider */
Otls_PROVIDER *Otls_PROVIDER_load(OPENtls_CTX *, const char *name);
int Otls_PROVIDER_unload(Otls_PROVIDER *prov);
int Otls_PROVIDER_available(OPENtls_CTX *, const char *name);

const Otls_PARAM *Otls_PROVIDER_gettable_params(const Otls_PROVIDER *prov);
int Otls_PROVIDER_get_params(const Otls_PROVIDER *prov, Otls_PARAM params[]);

/* Add a built in providers */
int Otls_PROVIDER_add_builtin(OPENtls_CTX *, const char *name,
                              Otls_provider_init_fn *init_fn);

/* Information */
const char *Otls_PROVIDER_name(const Otls_PROVIDER *prov);

# ifdef __cplusplus
}
# endif

#endif
