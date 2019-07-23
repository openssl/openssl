/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OPENSSL_NO_ARIA) && !defined(FIPS_MODE)

# include "internal/aria.h"

# define PROV_ARIA_CIPHER_ofb PROV_ARIA_CIPHER_ofb128
# define PROV_ARIA_CIPHER_cfb PROV_ARIA_CIPHER_cfb128

typedef struct prov_aria_key_st {
    PROV_GENERIC_KEY base;      /* Must be first */
    union {
        OSSL_UNION_ALIGN;
        ARIA_KEY ks;
    } ks;
} PROV_ARIA_KEY;

const PROV_GENERIC_CIPHER *PROV_ARIA_CIPHER_ecb(size_t keybits);
const PROV_GENERIC_CIPHER *PROV_ARIA_CIPHER_cbc(size_t keybits);
const PROV_GENERIC_CIPHER *PROV_ARIA_CIPHER_ofb128(size_t keybits);
const PROV_GENERIC_CIPHER *PROV_ARIA_CIPHER_cfb128(size_t keybits);
const PROV_GENERIC_CIPHER *PROV_ARIA_CIPHER_cfb1(size_t keybits);
const PROV_GENERIC_CIPHER *PROV_ARIA_CIPHER_cfb8(size_t keybits);
const PROV_GENERIC_CIPHER *PROV_ARIA_CIPHER_ctr(size_t keybits);

#endif /* OPENSSL_NO_ARIA */
