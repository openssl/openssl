/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_PARAM_TRIE_H
# define OSSL_CRYPTO_PARAM_TRIE_H
# pragma once

# include <openssl/params.h>
# include "internal/nelem.h"

typedef struct ossl_ptrie_s OSSL_PTRIE;
typedef unsigned char OSSL_PTRIE_PARAM_IDX;

OSSL_PTRIE *ossl_ptrie_new(const OSSL_PARAM *params);
void ossl_ptrie_free(OSSL_PTRIE *pt);
int ossl_ptrie_scan(const OSSL_PTRIE *pt, const OSSL_PARAM *params,
                    size_t n, OSSL_PTRIE_PARAM_IDX *indicies);
OSSL_PARAM *ossl_ptrie_locate(int idx, OSSL_PARAM *params,
                              OSSL_PTRIE_PARAM_IDX *indicies, const char *key);
const OSSL_PARAM *ossl_ptrie_locate_const(int idx, const OSSL_PARAM *params,
                                          OSSL_PTRIE_PARAM_IDX *indicies,
                                          const char *key);

#endif  /* OSSL_CRYPTO_PARAM_TRIE_H */
