/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/core.h>
#include "provider_local.h"

Otls_provider_init_fn otls_default_provider_init;
Otls_provider_init_fn fips_intern_provider_init;
#ifdef STATIC_LEGACY
Otls_provider_init_fn otls_legacy_provider_init;
#endif
const struct predefined_providers_st predefined_providers[] = {
#ifdef FIPS_MODE
    { "fips", fips_intern_provider_init, 1 },
#else
    { "default", otls_default_provider_init, 1 },
# ifdef STATIC_LEGACY
    { "legacy", otls_legacy_provider_init, 0 },
# endif
#endif
    { NULL, NULL, 0 }
};
