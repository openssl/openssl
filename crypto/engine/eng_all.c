/*
 * Copyright 2001-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "eng_local.h"

void ENGINE_load_builtin_engines(void)
{
    OPENtls_init_crypto(OPENtls_INIT_ENGINE_ALL_BUILTIN, NULL);
}

#ifndef OPENtls_NO_DEPRECATED_1_1_0
# if (defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__DragonFly__))
void ENGINE_setup_bsd_cryptodev(void)
{
}
# endif
#endif
