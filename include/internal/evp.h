/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_EVP_H
# define OSSL_INTERNAL_EVP_H

# include <openssl/evp.h>

# ifndef OPENSSL_NO_EC
/*
 * TODO(3.0) While waiting for more generic getters, we have these functions
 * as an interim solution.  This should be removed when the generic getters
 * appear.
 */
int evp_pkey_get_EC_KEY_curve_nid(const EVP_PKEY *pkey);
# endif
#endif
