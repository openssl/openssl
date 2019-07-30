/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* TODO(3.0) Figure out what flags are really needed */
#define AEAD_FLAGS (EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_FLAG_DEFAULT_ASN1     \
                       | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER      \
                       | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT        \
                       | EVP_CIPH_CUSTOM_COPY)
