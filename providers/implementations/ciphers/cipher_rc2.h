/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/rc2.h>
#include "prov/ciphercommon.h"

typedef struct prov_rc2_ctx_st {
    PROV_CIPHER_CTX base;      /* Must be first */
    union {
        OSSL_UNION_ALIGN;
        RC2_KEY ks;
    } ks;
    size_t key_bits;
} PROV_RC2_CTX;

#define PROV_CIPHER_HW_rc2_ofb128 PROV_CIPHER_HW_rc2_ofb64
#define PROV_CIPHER_HW_rc2_cfb128 PROV_CIPHER_HW_rc2_cfb64

const PROV_CIPHER_HW *PROV_CIPHER_HW_rc2_cbc(size_t keybits);
const PROV_CIPHER_HW *PROV_CIPHER_HW_rc2_ecb(size_t keybits);
const PROV_CIPHER_HW *PROV_CIPHER_HW_rc2_ofb64(size_t keybits);
const PROV_CIPHER_HW *PROV_CIPHER_HW_rc2_cfb64(size_t keybits);
