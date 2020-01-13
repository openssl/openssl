/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/core.h>

struct predefined_providers_st {
    const char *name;
    Otls_provider_init_fn *init;
    unsigned int is_fallback:1;
};

extern const struct predefined_providers_st predefined_providers[];
