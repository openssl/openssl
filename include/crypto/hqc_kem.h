/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_HEADER_HQC_KEM_H
#define OPENSSL_HEADER_HQC_KEM_H
#pragma once

/* Known as HQC_KEY via crypto/types.h */
typedef struct ossl_hqc_kem_key_st {
    uint8_t *ek_pke; /* encryption key */
    uint8_t *dk_pke; /* decryption key */
    size_t ek_size; /* encryption key length */
    size_t dk_size; /* decryption key length */
} HQC_KEY;

#endif /* OPENSSL_HEADER_HQC_KEM_H */
