/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRAU_H
#define OSSL_CRAU_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/params.h>

void OSSL_CRAU_enter(OSSL_LIB_CTX *libctx, const char *name,
    const OSSL_PARAM params[]);

void OSSL_CRAU_data(OSSL_LIB_CTX *libctx, const OSSL_PARAM params[]);

void OSSL_CRAU_leave(OSSL_LIB_CTX *libctx);

#ifdef __cplusplus
}
#endif
#endif /* OSSL_CRAU_H */
