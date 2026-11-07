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
#include <string.h>
#include <unistd.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include "internal/e_os.h"

static int deny_allocations;
static int fail_at;
static int allocation_attempts;
static int live_allocations;

static void *test_malloc(size_t size, const char *file, int line)
{
    void *ptr;

    if (deny_allocations && ++allocation_attempts >= fail_at && fail_at != 0) {
        return NULL;
    }
    ptr = malloc(size);
    if (ptr != NULL)
        ++live_allocations;
    return ptr;
}

static void *test_realloc(void *ptr, size_t size, const char *file, int line)
{
    void *result;

    if (deny_allocations && ++allocation_attempts >= fail_at && fail_at != 0) {
        return NULL;
    }
    result = realloc(ptr, size);
    if (result != NULL && ptr == NULL)
        ++live_allocations;
    return result;
}

static void test_free(void *ptr, const char *file, int line)
{
    if (ptr != NULL)
        --live_allocations;
    free(ptr);
}

/* Supported-module teardown must make progress with an exhausted allocator. */
int main(int argc, char **argv)
{
    int before, after, ret = 1, all;
    BIO *config_bio = NULL;
    CONF *config = NULL;

    alarm(15);
    if (argc != 4)
        return 2;
    all = strcmp(argv[1], "all") == 0;
    fail_at = atoi(argv[2]);
    if (!CRYPTO_set_mem_functions(test_malloc, test_realloc, test_free)
        || !OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL)
        || !CONF_module_add("allocation-test-one", NULL, NULL)
        || !CONF_module_add("allocation-test-two", NULL, NULL))
        goto end;
    config_bio = BIO_new(BIO_s_mem());
    config = NCONF_new(NULL);
    if (config_bio == NULL || config == NULL
        || BIO_printf(config_bio,
               "openssl_conf=modules\n[modules]\nlifecycle=config\n"
               "[config]\npath=%s\n",
               argv[3])
            <= 0
        || NCONF_load_bio(config, config_bio, NULL) <= 0
        || CONF_modules_load(config, NULL, 0) <= 0)
        goto end;
    NCONF_free(config);
    config = NULL;
    BIO_free(config_bio);
    config_bio = NULL;
    CONF_modules_finish();
    /* Initialise the error queue before denying allocations. */
    ERR_get_error();
    before = live_allocations;
    deny_allocations = 1;
    CONF_modules_unload(all);
    after = live_allocations;
    deny_allocations = 0;
    if (all && (allocation_attempts != 0 || after >= before))
        goto end;
    if (!all) {
        if (fail_at == 0 && after >= before)
            goto end;
        /* If reservation failed, full unload must still own every module. */
        CONF_modules_unload(1);
    }
    /* Repeated full unload is also allocation-free. */
    allocation_attempts = 0;
    deny_allocations = 1;
    CONF_modules_unload(1);
    deny_allocations = 0;
    if (allocation_attempts != 0)
        goto end;
    ret = 0;
end:
    deny_allocations = 0;
    NCONF_free(config);
    BIO_free(config_bio);
    OPENSSL_cleanup();
    ossl_cleanup_destructor();
    if (live_allocations != 0)
        ret = 1;
    fprintf(stderr, "unload allocation attempts=%d live=%d\n",
        allocation_attempts, live_allocations);
    return ret;
}
