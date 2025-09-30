/*
 * Copyright 2021-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>

#define FAKE_PASSPHRASE "Passphrase Testing"

/* Fake RSA provider implementation */
OSSL_PROVIDER *fake_rsa_start(OSSL_LIB_CTX *libctx);
void fake_rsa_finish(OSSL_PROVIDER *p);

OSSL_PARAM *fake_rsa_key_params(int priv);
void fake_rsa_restore_store_state(void);

/*
 * When fake_rsa_query_operation_name is set to a non-zero value,
 * query_operation_name() will return NULL.
 *
 * By default, it is 0, in which case query_operation_name() will return "RSA".
 */
extern unsigned fake_rsa_query_operation_name;
