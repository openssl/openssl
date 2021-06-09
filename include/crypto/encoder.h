/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/types.h>

OSSL_ENCODER *ossl_encoder_fetch_by_number(OSSL_LIB_CTX *libctx, int id,
                                           const char *properties);
int ossl_encoder_get_number(const OSSL_ENCODER *encoder);
void ossl_encoder_do_all_prefetched(OSSL_LIB_CTX *libctx,
                                    void (*user_fn)(OSSL_ENCODER *encoder,
                                                    void *arg),
                                    void *user_arg);
