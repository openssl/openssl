/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>

int ossl_prov_callback_from_dispatch(const OSSL_DISPATCH *fns);

int ossl_prov_generic_callback(OSSL_CALLBACK *cb, const OSSL_PARAM *params);
