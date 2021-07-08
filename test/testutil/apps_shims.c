/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include "apps.h"
#include "../testutil.h"

/* shim that avoids sucking in too much from apps/apps.c */

void *app_malloc(size_t sz, const char *what)
{
    void *vp;

    /*
     * This isn't ideal but it is what the app's app_malloc() does on failure.
     * Instead of exiting with a failure, abort() is called which makes sure
     * that there will be a good stack trace for debugging purposes.
     */
    if (!TEST_ptr(vp = OPENSSL_malloc(sz))) {
        TEST_info("Could not allocate %zu bytes for %s\n", sz, what);
        abort();
    }
    return vp;
}
