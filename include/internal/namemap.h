/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"

typedef struct ossl_namemap_st OSSL_NAMEMAP;

OSSL_NAMEMAP *ossl_namemap_stored(OPENSSL_CTX *libctx);

OSSL_NAMEMAP *ossl_namemap_new(void);
void ossl_namemap_free(OSSL_NAMEMAP *namemap);

int ossl_namemap_add(OSSL_NAMEMAP *namemap, const char *name);
const char *ossl_namemap_name(const OSSL_NAMEMAP *namemap, int number);
int ossl_namemap_number(const OSSL_NAMEMAP *namemap, const char *name);
