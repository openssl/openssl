/*
 * Copyright 2025-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_IOVEC_H
# define OSSL_IOVEC_H
# include <stddef.h>
# include <string.h>

/* Abstraction layer for iovec */
typedef struct ossl_iovec {
    void *data;
    size_t data_len;
} OSSL_IOVEC;

static inline void ossl_iovec_memcpy(unsigned char *dst,
                                     const OSSL_IOVEC *src,
                                     size_t len, size_t offset)
{
    size_t ptr = 0;

    while (offset >= (size_t)src[ptr].data_len) {
        offset -= src[ptr].data_len;
        ptr++;
    }

    while (len > 0) {
        size_t to_copy = src[ptr].data_len - offset;

        if (to_copy > len)
            to_copy = len;
        memcpy(dst, (unsigned char *)(src[ptr].data) + offset, to_copy);
        dst += to_copy;
        len -= to_copy;
        offset = 0;
        ptr++;
    }
}

#endif
