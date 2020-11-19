/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This header file preserves symbols from pre-3.0 OpenSSL.
 * It should never be included directly, as it's already included
 * by the public sslerr.h headers, and since it will go away some
 * time in the future.
 */

#ifndef OPENSSL_SSLERR_LEGACY_H
# define OPENSSL_SSLERR_LEGACY_H
# pragma once

# include <openssl/macros.h>
# include <openssl/symhacks.h>

# ifdef  __cplusplus
extern "C" {
# endif

# ifndef OPENSSL_NO_DEPRECATED_3_0
OSSL_DEPRECATEDIN_3_0 int ERR_load_SSL_strings(void);
# endif

# ifdef  __cplusplus
}
# endif
#endif

