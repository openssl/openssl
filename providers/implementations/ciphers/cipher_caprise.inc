/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Gettable context parameters for CAPRISE */
CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_START(caprise)
    OSSL_PARAM_double("caprise_s", NULL),
    OSSL_PARAM_double("caprise_beta", NULL),
    OSSL_PARAM_size_t("caprise_dim", NULL),
    OSSL_PARAM_uint("caprise_mode", NULL),
CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_END(caprise)

/* Settable context parameters for CAPRISE */
CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_START(caprise)
    OSSL_PARAM_double("caprise_s", NULL),
    OSSL_PARAM_double("caprise_beta", NULL),
    OSSL_PARAM_size_t("caprise_dim", NULL),
    OSSL_PARAM_uint("caprise_mode", NULL),
CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_END(caprise)
