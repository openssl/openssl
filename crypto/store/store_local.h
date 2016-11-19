/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/store.h>

struct store_info_st {
    int type;
    union {
        char *name;              /* when type == STORE_INFO_NAME */
        EVP_PKEY *pkey;          /* when type == STORE_INFO_PKEY */
        X509 *x509;              /* when type == STORE_INFO_X509 */
        X509_CRL *crl;           /* when type == STORE_INFO_CRL */
        void *data;              /* used internally */
    } _;
};

typedef struct scheme_loader_st {
    int no_free;
    char *scheme;
    STORE_loader_fn loader;
} SCHEME_LOADER;

int register_loader_int(SCHEME_LOADER *scheme_loader);
const SCHEME_LOADER *get_loader_int(const char *scheme);
int unregister_loader_int(const char *scheme);
void destroy_loaders_int(void);
