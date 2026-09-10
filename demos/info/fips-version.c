/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>

int main(int argc, char **argv)
{
    int ret = EXIT_FAILURE;
    OSSL_LIB_CTX *libctx;
    OSSL_PROVIDER *fips_provider = NULL;
    OSSL_PARAM params[2];
    char *version;

    /* Replace this with your libctx if you are using a non-default one */
    libctx = NULL;

    /* Check if the FIPS provider is available in this libctx */
    if (!OSSL_PROVIDER_available(libctx, "fips")) {
        puts("FIPS provider is not available");
        goto done;
    }

    /* Load the FIPS provider */
    fips_provider = OSSL_PROVIDER_load(libctx, "fips");
    if (fips_provider == NULL) {
        puts("Failed to load FIPS provider");
        goto done;
    }

    /* Query the FIPS provider version */
    params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION,
        &version, 0);
    params[1] = OSSL_PARAM_construct_end();
    OSSL_PARAM_set_all_unmodified(params);
    if (!OSSL_PROVIDER_get_params(fips_provider, params)) {
        puts("Failed to query FIPS provider version");
        goto done;
    }

    /* Check if the FIPS provider returned a version to us */
    if (!OSSL_PARAM_modified(params)) {
        puts("FIPS provider failed to set version");
        goto done;
    }

    printf("FIPS provider version is %s\n", version);
    ret = EXIT_SUCCESS;
done:
    OSSL_PROVIDER_unload(fips_provider);
    return ret;
}
