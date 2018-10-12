/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#ifndef HEADER_ENGINE_LOADER_H
#define HEADER_ENGINE_LOADER_H

# include <openssl/store.h>

int setup_engine_loader(void);
void destroy_engine_loader(void);
# define APP_STORE_C_LOAD_PRIVKEY      (OSSL_STORE_C_CUSTOM_START + 0)
# define APP_STORE_C_LOAD_PUBKEY       (OSSL_STORE_C_CUSTOM_START + 1)

#endif
