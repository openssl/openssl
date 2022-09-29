/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_LMS_H
# define OPENSSL_LMS_H
# pragma once

# include <openssl/macros.h>
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define HEADER_KDF_H
# endif

# include <stdarg.h>
# include <stddef.h>
# include <openssl/types.h>
# include <openssl/core.h>

# ifdef __cplusplus
extern "C" {
# endif

int OSSL_HSS_verify(const unsigned char *pub, size_t publen,
                    const unsigned char *sig, size_t siglen,
                    const unsigned char *msg, size_t msglen);

# ifdef __cplusplus
}
# endif
#endif
