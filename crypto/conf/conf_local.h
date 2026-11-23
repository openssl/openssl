/*
 * Copyright 2018-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OSSL_LIBCRYPTO_CONF_CONF_LOCAL_H)
#define OSSL_LIBCRYPTO_CONF_CONF_LOCAL_H

#include <openssl/conftypes.h>
void ossl_config_add_ssl_module(void);

/**
 * @brief Register the "secret_check" configuration module, which turns
 * the check of private keys and seeds on or off for the process.
 * @see CRYPTO_secret_check_enable(3), config(5)
 */
void ossl_config_add_secret_check_module(void);

#endif /* !defined(OSSL_LIBCRYPTO_CONF_CONF_LOCAL_H) */
