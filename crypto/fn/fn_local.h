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

/*
 * 64-bit processor with LP64 ABI
 */
# ifdef SIXTY_FOUR_BIT_LONG
#  define OSSL_FN_ULLONG        unsigned long long
#  define OSSL_FN_BITS4         32
#  define OSSL_FN_MASK2         (0xffffffffffffffffL)
#  define OSSL_FN_MASK2l        (0xffffffffL)
#  define OSSL_FN_MASK2h        (0xffffffff00000000L)
#  define OSSL_FN_MASK2h1       (0xffffffff80000000L)
#  define OSSL_FN_DEC_CONV      (10000000000000000000UL)
#  define OSSL_FN_DEC_NUM       19
#  define OSSL_FN_DEC_FMT1      "%lu"
#  define OSSL_FN_DEC_FMT2      "%019lu"
# endif

/*
 * 64-bit processor other than LP64 ABI
 */
# ifdef SIXTY_FOUR_BIT
#  undef BN_LLONG
#  undef BN_ULLONG
#  define OSSL_FN_BITS4         32
#  define OSSL_FN_MASK2         (0xffffffffffffffffLL)
#  define OSSL_FN_MASK2l        (0xffffffffL)
#  define OSSL_FN_MASK2h        (0xffffffff00000000LL)
#  define OSSL_FN_MASK2h1       (0xffffffff80000000LL)
#  define OSSL_FN_DEC_CONV      (10000000000000000000ULL)
#  define OSSL_FN_DEC_NUM       19
#  define OSSL_FN_DEC_FMT1      "%llu"
#  define OSSL_FN_DEC_FMT2      "%019llu"
# endif

# ifdef THIRTY_TWO_BIT
#  ifdef BN_LLONG
#   if defined(_WIN32) && !defined(__GNUC__)
#    define OSSL_FN_ULLONG      unsigned __int64
#   else
#    define OSSL_FN_ULLONG      unsigned long long
#   endif
#  endif
#  define OSSL_FN_BITS4         16
#  define OSSL_FN_MASK2         (0xffffffffL)
#  define OSSL_FN_MASK2l        (0xffff)
#  define OSSL_FN_MASK2h1       (0xffff8000L)
#  define OSSL_FN_MASK2h        (0xffff0000L)
#  define OSSL_FN_DEC_CONV      (1000000000L)
#  define OSSL_FN_DEC_NUM       9
#  define OSSL_FN_DEC_FMT1      "%u"
#  define OSSL_FN_DEC_FMT2      "%09u"
# endif

struct ossl_fn_st {
    /* Flag: alloced with OSSL_FN_new() or  OSSL_FN_secure_new() */
    unsigned int is_dynamically_allocated : 1;
    /* Flag: alloced with OSSL_FN_secure_new() */
    unsigned int is_securely_allocated : 1;
    /* Flag: the caller holds a pointer to this OSSL_FN as well as the BIGNUM that wraps it */
    unsigned int is_acquired : 1;
    /* Flag: the number is negative */
    unsigned int is_negative : 1;

    /*
     * The d array, with its size in number of BN_ULONG.
     * This stores the number itself
     */
    size_t dsize;
    OSSL_FN_ULONG d[];
};

#endif
