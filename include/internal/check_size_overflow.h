/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_CHECK_SIZE_OVERFLOW_H
# define OSSL_INTERNAL_CHECK_SIZE_OVERFLOW_H

# include <limits.h>
# include <stdbool.h>
# include <stdint.h>

# include "internal/common.h"

# include <openssl/cryptoerr.h>
# include <openssl/err.h>

/*
 * A small (premature) optimisation:  do not check for multiplication overflow
 * if neither of the operands is at least half the type size.
 */
# define HALF_SIZE_T ((size_t) 1 << (sizeof(size_t) * (CHAR_BIT / 2)))

static inline bool is_size_overflow(size_t num, size_t size, size_t *bytes,
                                    const char *file, int line)
{
    *bytes = num * size;

    if (ossl_unlikely(((num | size) >= HALF_SIZE_T)
                      && size && ((*bytes / size) != num))) {
        if (file != NULL || line != 0) {
            ERR_new();
            ERR_set_debug(file, line, NULL);
            ERR_set_error(ERR_LIB_CRYPTO, CRYPTO_R_INTEGER_OVERFLOW, NULL);
        }

        return true;
    }

    return false;
}

#endif /* OSSL_INTERNAL_CHECK_SIZE_OVERFLOW_H */
