/*
 * Copyright 2020-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OSSL_LIBCRYPTO_PKCS7_PK7_LOCAL_H)
#define OSSL_LIBCRYPTO_PKCS7_PK7_LOCAL_H

#include "crypto/pkcs7.h"

/*
 * The public PKCS7 state field once held PKCS7_S_HEADER/BODY/TAIL; those
 * values are no longer used but remain public.  Use a separate bit of the
 * field, clear of the public values, as an internal flag.
 *
 * Set when streaming is set up, where the encoder writes the content out.
 * When it is not set and the content is not detached, the content octet
 * string is filled at dataFinal time from the memory BIO PKCS7_dataInit()
 * creates.
 */
#define PKCS7_STATE_STREAMING 0x100

STACK_OF(X509) *pkcs7_get0_certificates(const PKCS7 *p7);
const PKCS7_CTX *ossl_pkcs7_get0_ctx(const PKCS7 *p7);
OSSL_LIB_CTX *ossl_pkcs7_ctx_get0_libctx(const PKCS7_CTX *ctx);
const char *ossl_pkcs7_ctx_get0_propq(const PKCS7_CTX *ctx);

int ossl_pkcs7_ctx_propagate(const PKCS7 *from, PKCS7 *to);

#endif /* !defined(OSSL_LIBCRYPTO_PKCS7_PK7_LOCAL_H) */
