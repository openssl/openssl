/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_ENDIAN_H
# define OSSL_INTERNAL_ENDIAN_H

# if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
#  define DECLARE_IS_ENDIAN
#  define IS_LITTLE_ENDIAN (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#  define IS_BIG_ENDIAN (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
# else
#  define DECLARE_IS_ENDIAN \
    const union { \
        long one; \
        char little; \
    } ossl_is_endian = { 1 }

#  define IS_LITTLE_ENDIAN (ossl_is_endian.little != 0)
#  define IS_BIG_ENDIAN    (ossl_is_endian.little == 0)
# endif

#endif
