/*
 * Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifdef FIPS_MODULE
#include <openssl/types.h>

#define FIPSPARAMS_AS_HEADER
#include "providers/fips/fipsparams.inc"
#undef FIPSPARAMS_AS_HEADER

int ossl_fips_config(OSSL_LIB_CTX *libctx, enum fips_config_id id);

#endif
