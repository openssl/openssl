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

/* Abstraction layer for iovec */
struct ossl_iovec {
    void *data;
    size_t data_len;
};

#endif