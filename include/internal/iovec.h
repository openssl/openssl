/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_IOVEC_H
# define OSSL_INTERNAL_IOVEC_H
# pragma once

# include <string.h>
# include <openssl/e_os2.h>

static ossl_inline void ossl_iovec_memcpy(unsigned char *dst,
                                          const struct iovec *src,
                                          size_t len, size_t offset)
{
    size_t ptr = 0;
    
    while (offset >= (size_t)src[ptr].iov_len) {
        offset -= src[ptr].iov_len;
        ptr++;
    }

    while (len > 0) {
        size_t to_copy = src[ptr].iov_len - offset;

        if (to_copy > len)
            to_copy = len;
        memcpy(dst, (unsigned char *)(src[ptr].iov_base) + offset, to_copy);
        dst += to_copy;
        len -= to_copy;
        offset = 0;
        ptr++;
    }
}

#endif
