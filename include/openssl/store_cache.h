/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_STORE_CACHE_H
# define HEADER_STORE_CACHE_H

# include <openssl/store.h>

# ifdef  __cplusplus
extern "C" {
# endif

/*-
 *  The main OSSL_STORE_CACHED functions.
 *  ------------------------------------
 *
 *  These functions offer the same functionality as the main OSSL_STORE
 *  functions, plus the possibility to attach one or more OSSL_STOREs
 *  to a cache
 */

typedef struct ossl_store_cache_st OSSL_STORE_CACHE;

OSSL_STORE_CACHE *OSSL_STORE_CACHE_new(void);
OSSL_STORE_CTX *OSSL_STORE_CACHED_open(OSSL_STORE_CACHE *cache, const char *uri,
                                       uint32_t flags,
                                       const UI_METHOD *ui_method,
                                       void *ui_data,
                                       OSSL_STORE_post_process_info_fn
                                       post_process, void *post_process_data);
void OSSL_STORE_CACHE_free(OSSL_STORE_CACHE *cache);

# define OSSL_STORE_CACHE_FLAG_CACHE_ONLY       0x0001

# ifdef  __cplusplus
}
# endif
#endif
