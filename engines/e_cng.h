/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <windows.h>
#include <openssl/safestack.h>

DEFINE_SPECIAL_STACK_OF(LPWSTR, WCHAR)

typedef struct store_lookup_fns_st {
    void *(*init)(STORE_LOADER_CTX *ctx);
    STORE_INFO *(*load)(void *lookup_tcx);
    int (*eof)(void *lookup_tcx);
    int (*error)(void *lookup_tcx);
    int (*clean)(void *lookup_tcx);
} STORE_LOOKUP_FNS;
DEFINE_STACK_OF_CONST(STORE_LOOKUP_FNS)
