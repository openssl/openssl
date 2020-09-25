/*
 * Copyright 2018-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../testutil.h"
#include <openssl/provider.h>
#include <string.h>

int test_get_libctx(OPENSSL_CTX **libctx,
                    OSSL_PROVIDER **default_null_provider,
                    OSSL_PROVIDER **provider, int argn, const char *usage)
{
    const char *module_name;

    if (!TEST_ptr(module_name = test_get_argument(argn))) {
        TEST_error("usage: <prog> %s", usage);
        return 0;
    }
    if (strcmp(module_name, "none") != 0) {
        const char *config_fname = test_get_argument(argn + 1);

        *default_null_provider = OSSL_PROVIDER_load(NULL, "null");
        *libctx = OPENSSL_CTX_new();
        if (!TEST_ptr(*libctx)) {
            TEST_error("Failed to create libctx\n");
            goto err;
        }

        if (config_fname != NULL
                && !TEST_true(OPENSSL_CTX_load_config(*libctx, config_fname))) {
            TEST_error("Error loading config file %s\n", config_fname);
            goto err;
        }

        *provider = OSSL_PROVIDER_load(*libctx, module_name);
        if (!TEST_ptr(*provider)) {
            TEST_error("Failed to load provider %s\n", module_name);
            goto err;
        }
    }
    return 1;

 err:
    ERR_print_errors_fp(stderr);
    return 0;
}
