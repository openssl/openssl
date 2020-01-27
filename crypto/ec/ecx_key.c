/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include "crypto/ecx.h"

ECX_KEY *ecx_key_new(size_t keylen, int haspubkey)
{
    ECX_KEY *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL)
        return NULL;

    ret->haspubkey = haspubkey;
    ret->keylen = keylen;
    ret->references = 1;

    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(ret);
        return NULL;
    }

    return ret;
}

void ecx_key_free(ECX_KEY *key)
{
    int i;

    if (key == NULL)
        return;

    CRYPTO_DOWN_REF(&key->references, &i, key->lock);
    REF_PRINT_COUNT("ECX_KEY", r);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    OPENSSL_secure_clear_free(key->privkey, key->keylen);
    CRYPTO_THREAD_lock_free(key->lock);
    OPENSSL_free(key);
}

int ecx_key_up_ref(ECX_KEY *key)
{
    int i;

    if (CRYPTO_UP_REF(&key->references, &i, key->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("ECX_KEY", key);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

unsigned char *ecx_key_allocate_privkey(ECX_KEY *key)
{
    key->privkey = OPENSSL_secure_zalloc(key->keylen);

    return key->privkey;
}
