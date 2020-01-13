/*
 * Copyright 2017 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include "output.h"
#include "tu_local.h"

int opentls_error_cb(const char *str, size_t len, void *u)
{
    return test_printf_stderr("%s", str);
}
