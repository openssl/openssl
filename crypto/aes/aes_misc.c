/*
 * Copyright 2002-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/opentlsv.h>
#include <opentls/aes.h>
#include "aes_local.h"

#ifndef OPENtls_NO_DEPRECATED_3_0
const char *AES_options(void)
{
# ifdef FULL_UNROLL
    return "aes(full)";
# else
    return "aes(partial)";
# endif
}
#endif
