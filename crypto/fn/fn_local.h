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

# include <string.h>
# include <openssl/opensslconf.h>
# include <openssl/e_os2.h>
# include "internal/common.h"
# include "crypto/fn.h"
# include "crypto/fn_intern.h"

# if OSSL_FN_BYTES == 4
/* 32-bit systems */
#  define OSSL_FN_MASK          UINT32_MAX
# elif OSSL_FN_BYTES == 8
/* 64-bit systems */
#  define OSSL_FN_MASK          UINT64_MAX
# else
#  error "OpenSSL doesn't support large numbers on this platform"
# endif

# define OSSL_FN_HIGH_BIT_MASK  (OSSL_FN_ULONG_C(1) << (OSSL_FN_BYTES * 8 - 1))

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

/*
 * Internal functions to support BIGNUM's bn_expand_internal, BN_copy, and
 * similar.
 * The caller must ensure that src and dest are not NULL.
 * With ossl_fn_copy_internal, bn_words may be given -1 to signify that the
 * number of BN_ULONG should be found in src.
 */
static ossl_inline OSSL_FN *ossl_fn_copy_internal_limbs(OSSL_FN *dest,
                                                        const OSSL_FN_ULONG *src,
                                                        int limbs)
{
    if (ossl_unlikely(dest->dsize < limbs))
        return NULL;
    memcpy(dest->d, src, limbs * sizeof(dest->d[0]));
    memset(dest->d + limbs, 0, (dest->dsize - limbs) * sizeof(dest->d[0]));
    return dest;
}

static ossl_inline OSSL_FN *ossl_fn_copy_internal(OSSL_FN *dest,
                                                  const OSSL_FN *src,
                                                  int bn_words)
{
    int words = bn_words < 0 ? src->dsize : bn_words;

    if (ossl_fn_copy_internal_limbs(dest, src->d, words) == NULL)
        return NULL;
    return dest;
}

#endif
