/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/self_test.h>

static OSSL_CALLBACK *ossl_self_test_cb = NULL;
void OSSL_SELF_TEST_set_callback(OSSL_CALLBACK *cb)
{
    ossl_self_test_cb = cb;
}
OSSL_CALLBACK *OSSL_SELF_TEST_get_callback(void)
{
    return ossl_self_test_cb;
}
