/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_FIPS_H
# define OSSL_INTERNAL_FIPS_H
# pragma once

# ifdef FIPS_MODULE

/* Return 1 if the FIPS self tests are running and 0 otherwise */
int ossl_fips_self_testing(void);

/* Deferred KAT tests categories */
#  define OSSL_DEFERRED_KAT_INTEGRITY 0
#  define OSSL_DEFERRED_KAT_CIPHER 1
#  define OSSL_DEFERRED_KAT_ASYM_CIPHER 2
#  define OSSL_DEFERRED_KAT_ASYM_KEYGEN 3
#  define OSSL_DEFERRED_KAT_KEM 4
#  define OSSL_DEFERRED_KAT_DIGEST 5
#  define OSSL_DEFERRED_KAT_SIGNATURE 6
#  define OSSL_DEFERRED_KAT_KDF 7
#  define OSSL_DEFERRED_KAT_KA 8
#  define OSSL_DEFERRED_MAX 9

struct ossl_deferred_test_st {
    const char *algorithm;
    int category;
    int pass;
};

typedef struct ossl_deferred_test_st OSSL_DEFERRED_TEST;

int FIPS_deferred_self_tests(OSSL_LIB_CTX *libctx, OSSL_DEFERRED_TEST tests[]);

# endif /* FIPS_MODULE */

#endif
