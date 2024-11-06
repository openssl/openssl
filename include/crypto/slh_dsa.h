/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal SLH_DSA functions for other submodules, not for application use */

#ifndef OSSL_CRYPTO_SLH_DSA_H
# define OSSL_CRYPTO_SLH_DSA_H

# pragma once
# include <openssl/e_os2.h>
# include <openssl/types.h>
# include "crypto/types.h"

SLH_DSA_KEY *ossl_slh_dsa_key_new(OSSL_LIB_CTX *libctx, const char *alg);
void ossl_slh_dsa_key_free(SLH_DSA_KEY *key);
int ossl_slh_dsa_key_up_ref(SLH_DSA_KEY *key);
int ossl_slh_dsa_key_equal(const SLH_DSA_KEY *key1, const SLH_DSA_KEY *key2,
                           int selection);
int ossl_slh_dsa_key_has(const SLH_DSA_KEY *key, int selection);
int ossl_slh_dsa_key_fromdata(SLH_DSA_KEY *key, const OSSL_PARAM *params);

#endif /* OSSL_CRYPTO_SLH_DSA_H */
