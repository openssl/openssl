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
#define CRYPTO_GLOCK_INIT         0
#define CRYPTO_GLOCK_BIO_LOOKUP   1
#define CRYPTO_GLOCK_BIO_TYPE     2
#define CRYPTO_GLOCK_RAND_METH    3
#define CRYPTO_GLOCK_RAND_ENGINE  4
#define CRYPTO_GLOCK_ENGINE       5
#define CRYPTO_GLOCK_EX_DATA      6
#define CRYPTO_GLOCK_OBJ          7
#define CRYPTO_GLOCK_REGISTRY     8
#define CRYPTO_GLOCK_ERR_STRING   9
#define CRYPTO_GLOCK_DRBG        10
#define CRYPTO_GLOCK_PRIV_DRBG   11
#define CRYPTO_GLOCK_RAND_BYTES  12
#define CRYPTO_GLOCK_SEC_MALLOC  13
#define CRYPTO_NUM_GLOCKS        14

int OPENSSL_LOCK_lock(int index);
int OPENSSL_LOCK_unlock(int index);
