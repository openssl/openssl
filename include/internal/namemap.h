/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"

const char *ossl_namemap_name(OPENSSL_CTX *libctx, int number);
int ossl_namemap_number(OPENSSL_CTX *libctx, const char *name);
int ossl_namemap_new(OPENSSL_CTX *libctx, const char *name);
