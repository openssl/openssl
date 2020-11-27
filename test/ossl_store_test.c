/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include "testutil.h"

#ifndef PATH_MAX
# if defined(_WIN32) && defined(_MAX_PATH)
#  define PATH_MAX _MAX_PATH
# else
#  define PATH_MAX 4096
# endif
#endif

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_INFILE,
    OPT_DATADIR,
    OPT_TEST_ENUM
} OPTION_CHOICE;

static const char *infile = NULL;
static const char *datadir = NULL;

static int test_store_open(void)
{
    int ret = 0;
    OSSL_STORE_CTX *sctx = NULL;
    OSSL_STORE_SEARCH *search = NULL;
    UI_METHOD *ui_method = NULL;

    ret = TEST_ptr(search = OSSL_STORE_SEARCH_by_alias("nothing"))
          && TEST_ptr(ui_method= UI_create_method("DummyUI"))
          && TEST_ptr(sctx = OSSL_STORE_open_ex(infile, NULL, NULL, ui_method,
                                                NULL, NULL, NULL))
          && TEST_false(OSSL_STORE_find(sctx, NULL))
          && TEST_true(OSSL_STORE_find(sctx, search));
    UI_destroy_method(ui_method);
    OSSL_STORE_SEARCH_free(search);
    OSSL_STORE_close(sctx);
    return ret;
}

static int test_store_search_by_key_fingerprint_fail(void)
{
    int ret;
    OSSL_STORE_SEARCH *search = NULL;

    ret = TEST_ptr_null(search = OSSL_STORE_SEARCH_by_key_fingerprint(
                                     EVP_sha256(), NULL, 0));
    OSSL_STORE_SEARCH_free(search);
    return ret;
}

static int get_params(const char *uri, const char *type)
{
    EVP_PKEY *pkey = NULL;
    OSSL_STORE_CTX *ctx = NULL;
    OSSL_STORE_INFO *info;
    int ret = 0;

    ctx = OSSL_STORE_open_ex(uri, NULL, NULL, NULL, NULL, NULL, NULL);
    if (!TEST_ptr(ctx))
        goto err;

    while (!OSSL_STORE_eof(ctx)
            && (info = OSSL_STORE_load(ctx)) != NULL
            && pkey == NULL) {
        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PARAMS) {
            pkey = OSSL_STORE_INFO_get1_PARAMS(info);
        }
        OSSL_STORE_INFO_free(info);
        info = NULL;
    }

    if (pkey != NULL)
        ret = EVP_PKEY_is_a(pkey, type);
    EVP_PKEY_free(pkey);

 err:
    OSSL_STORE_close(ctx);
    return ret;
}

static int test_store_get_params(int idx)
{
    const char *type;
    char uri[PATH_MAX];

    switch(idx) {
#ifndef OPENSSL_NO_DH
    case 0:
        type = "DH";
        break;
    case 1:
        type = "DHX";
        break;
#else
    case 0:
    case 1:
        return 1;
#endif
    case 2:
#ifndef OPENSSL_NO_DSA
        type = "DSA";
        break;
#else
        return 1;
#endif
    default:
        TEST_error("Invalid test index");
        return 0;
    }

    if (!TEST_true(BIO_snprintf(uri, sizeof(uri), "%s/%s-params.pem",
                                datadir, type)))
        return 0;

    TEST_info("Testing uri: %s", uri);
    if (!TEST_true(get_params(uri, type)))
        return 0;

    return 1;
}


const OPTIONS *test_get_options(void)
{
    static const OPTIONS test_options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "in", OPT_INFILE, '<', },
        { "data", OPT_DATADIR, 's' },
        { NULL }
    };
    return test_options;
}

int setup_tests(void)
{
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_INFILE:
            infile = opt_arg();
            break;
        case OPT_DATADIR:
            datadir = opt_arg();
            break;
        case OPT_TEST_CASES:
           break;
        default:
        case OPT_ERR:
            return 0;
        }
    }

    if (datadir == NULL) {
        TEST_error("No datadir specified");
        return 0;
    }

    ADD_TEST(test_store_open);
    ADD_TEST(test_store_search_by_key_fingerprint_fail);
    ADD_ALL_TESTS(test_store_get_params, 3);
    return 1;
}
