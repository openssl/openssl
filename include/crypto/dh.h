/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/dh.h>
#include "internal/ffc.h"

int dh_generate_ffc_parameters(OPENSSL_CTX *libctx, DH *dh, int bits,
                               int qbits, int gindex, BN_GENCB *cb);

int dh_compute_key(OPENSSL_CTX *ctx, unsigned char *key, const BIGNUM *pub_key,
                   DH *dh);
int dh_compute_key_padded(OPENSSL_CTX *ctx, unsigned char *key,
                          const BIGNUM *pub_key, DH *dh);
FFC_PARAMS *dh_get0_params(DH *dh);
int dh_get0_nid(const DH *dh);
