/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Indexes into the global arrays of glocks and names. */
/*
 * Be careful about lock ordering requirements here!  If there is any codepath
 * in which more than one of these locks is held at the same time, order
 * the corresponding indices so that the lock that is first in the order has
 * the lower index.
 */
enum {
    CRYPTO_GLOCK_INIT = 0,
    CRYPTO_GLOCK_BIO_LOOKUP,
    CRYPTO_GLOCK_BIO_TYPE,
    CRYPTO_GLOCK_RAND_METH,
    CRYPTO_GLOCK_RAND_ENGINE,
    CRYPTO_GLOCK_ENGINE,
    CRYPTO_GLOCK_EX_DATA,
    CRYPTO_GLOCK_OBJ,
    CRYPTO_GLOCK_REGISTRY,
    CRYPTO_GLOCK_ERR_STRING,
    CRYPTO_GLOCK_DRBG,
    CRYPTO_GLOCK_PRIV_DRBG,
    CRYPTO_GLOCK_RAND_BYTES,
    CRYPTO_GLOCK_SEC_MALLOC,
    CRYPTO_NUM_GLOCKS
};

extern CRYPTO_RWLOCK *openssl_locks[CRYPTO_NUM_GLOCKS];
