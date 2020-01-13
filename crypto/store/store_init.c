/*
 * Copyright 2016-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/err.h>
#include "crypto/store.h"
#include "store_local.h"

static CRYPTO_ONCE store_init = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(do_store_init)
{
    return OPENtls_init_crypto(0, NULL)
        && otls_store_file_loader_init();
}

int otls_store_init_once(void)
{
    if (!RUN_ONCE(&store_init, do_store_init)) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_INIT_ONCE, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

void otls_store_cleanup_int(void)
{
    otls_store_destroy_loaders_int();
}
