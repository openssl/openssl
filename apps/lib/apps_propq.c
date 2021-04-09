/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stddef.h>
#include "apps_propq.h"

static const char *app_propq = NULL;

<<<<<<< HEAD:apps/lib/apps_propq.c
int app_set_propq(const char *arg)
=======
/* shim that avoids sucking in too much from apps/apps.c */

void *app_malloc(size_t sz, const char *what)
>>>>>>> b1c908f421b3466aecf980603132bcab89d1ce99:test/testutil/apps_mem.c
{
    app_propq = arg;
    return 1;
}

const char *app_get0_propq(void)
{
    return app_propq;
}


