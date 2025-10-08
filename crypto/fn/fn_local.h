/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_FN_LOCAL_H
# define OSSL_CRYPTO_FN_LOCAL_H

# include <openssl/opensslconf.h>
# include "crypto/fn.h"

struct ossl_fn_st {
    /* Flag: alloced with OSSL_FN_new() or  OSSL_FN_secure_new() */
    unsigned int is_dynamically_allocated : 1;
    /* Flag: alloced with OSSL_FN_secure_new() */
    unsigned int is_securely_allocated : 1;

    /*
     * The d array, with its size in number of OSSL_FN_ULONG.
     * This stores the number itself.
     *
     * Note: |dsize| is an int, because it turns out that some lower level
     * (possibly assembler) functions expect that type (especially, that
     * type size).
     * This deviates from the design in doc/designs/fixed-size-large-numbers.md
     */
    int dsize;
    OSSL_FN_ULONG d[];
};

#endif
