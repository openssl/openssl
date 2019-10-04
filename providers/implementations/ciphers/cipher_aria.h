/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/aria.h"
#include "prov/ciphercommon.h"

typedef struct prov_aria_ctx_st {
    PROV_CIPHER_CTX base;      /* Must be first */
    union {
        OSSL_UNION_ALIGN;
        ARIA_KEY ks;
    } ks;
} PROV_ARIA_CTX;


# define PROV_CIPHER_HW_aria_ofb PROV_CIPHER_HW_aria_ofb128
# define PROV_CIPHER_HW_aria_cfb PROV_CIPHER_HW_aria_cfb128
const PROV_CIPHER_HW *PROV_CIPHER_HW_aria_ecb(size_t keybits);
const PROV_CIPHER_HW *PROV_CIPHER_HW_aria_cbc(size_t keybits);
const PROV_CIPHER_HW *PROV_CIPHER_HW_aria_ofb128(size_t keybits);
const PROV_CIPHER_HW *PROV_CIPHER_HW_aria_cfb128(size_t keybits);
const PROV_CIPHER_HW *PROV_CIPHER_HW_aria_cfb1(size_t keybits);
const PROV_CIPHER_HW *PROV_CIPHER_HW_aria_cfb8(size_t keybits);
const PROV_CIPHER_HW *PROV_CIPHER_HW_aria_ctr(size_t keybits);
