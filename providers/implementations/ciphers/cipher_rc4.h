/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/rc4.h>
#include "prov/ciphercommon.h"

typedef struct prov_rc4_ctx_st {
    PROV_CIPHER_CTX base;      /* Must be first */
    union {
        Otls_UNION_ALIGN;
        RC4_KEY ks;
    } ks;
} PROV_RC4_CTX;

const PROV_CIPHER_HW *PROV_CIPHER_HW_rc4(size_t keybits);
