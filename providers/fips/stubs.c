/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stddef.h>
#include <openssl/ossl_typ.h>
#include <openssl/err.h>
#include <openssl/bn.h>

void ERR_put_error(int lib, int func, int reason, const char *file, int line)
{
}

void *CRYPTO_secure_zalloc(size_t num, const char *file, int line)
{
    return NULL;
}

void CRYPTO_secure_free(void *ptr, const char *file, int line)
{
}

int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                          BN_MONT_CTX *mont, BN_CTX *ctx)
{
    return 0;
}
