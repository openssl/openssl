/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Utility overflow checking and reporting functions
 */

#ifndef OSSL_INTERNAL_CHECK_SIZE_OVERFLOW_H
# define OSSL_INTERNAL_CHECK_SIZE_OVERFLOW_H

# include "internal/common.h"

# include <openssl/cryptoerr.h>
# include <openssl/err.h>

/*
 * A helper routine to report memory allocation errors.
 * Similar to the ERR_raise() macro, but accepts explicit file/line arguments,
 * pre-defines the library to ERR_LIB_CRYPTO, and avoids emitting an error
 * if both file set to NULL and line set to 0.
 */
static ossl_inline ossl_unused void
ossl_report_alloc_err_ex(const char * const file, const int line,
                         const int reason)
{
    /*
     * ossl_err_get_state_int() in err.c uses CRYPTO_zalloc(num, NULL, 0) for
     * ERR_STATE allocation. Prevent mem alloc error loop while reporting error.
     */
    if (file != NULL || line != 0) {
        ERR_new();
        ERR_set_debug(file, line, NULL);
        ERR_set_error(ERR_LIB_CRYPTO, reason, NULL);
    }
}

/* Report a memory allocation failure. */
static inline void
ossl_report_alloc_err(const char * const file, const int line)
{
    ossl_report_alloc_err_ex(file, line, ERR_R_MALLOC_FAILURE);
}

#endif /* OSSL_INTERNAL_CHECK_SIZE_OVERFLOW_H */
