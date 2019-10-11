/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/idea.h>
#include "prov/ciphercommon.h"

typedef struct prov_idea_ctx_st {
    PROV_CIPHER_CTX base;      /* Must be first */
    union {
        OSSL_UNION_ALIGN;
        IDEA_KEY_SCHEDULE ks;
    } ks;
} PROV_IDEA_CTX;

const PROV_CIPHER_HW *PROV_CIPHER_HW_idea_cbc(size_t keybits);
const PROV_CIPHER_HW *PROV_CIPHER_HW_idea_ecb(size_t keybits);
const PROV_CIPHER_HW *PROV_CIPHER_HW_idea_ofb64(size_t keybits);
const PROV_CIPHER_HW *PROV_CIPHER_HW_idea_cfb64(size_t keybits);
