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

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_CRAU
#include <openssl/params.h>
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Opens a new event context with the given |name| and the
 * optional event data in |params|, associates it with the given
 * libctx.  Should be closed by a matching OSSL_CRAU_leave.
 */
void OSSL_CRAU_enter(OSSL_LIB_CTX *libctx, const char *name,
    const OSSL_PARAM params[]);

/*
 * Asserts event data in |params| in the current event context
 * associated with the given libctx.
 */
void OSSL_CRAU_data(OSSL_LIB_CTX *libctx, const OSSL_PARAM params[]);

/*
 * Closes the event context associated with the given libctx.  The
 * event context should have been opened by a matching
 * OSSL_CRAU_enter.
 */
void OSSL_CRAU_leave(OSSL_LIB_CTX *libctx);

#ifdef __cplusplus
}
#endif
#endif
#endif /* OSSL_CRAU_H */
