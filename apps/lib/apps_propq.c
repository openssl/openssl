/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stddef.h>

static const char *app_propq = NULL;

int app_set_propq(const char *arg)
{
    app_propq = arg;
    return 1;
}

const char *app_get0_propq(void)
{
    return app_propq;
}


