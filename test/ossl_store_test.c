/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/store.h>
#include <openssl/ui.h>
#include "testutil.h"

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_INFILE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

static const char *infile = NULL;

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

const OPTIONS *test_get_options(void)
{
    static const OPTIONS test_options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "in", OPT_INFILE, '<', },
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
        case OPT_TEST_CASES:
           break;
        default:
        case OPT_ERR:
            return 0;
        }
    }

    ADD_TEST(test_store_open);
    ADD_TEST(test_store_search_by_key_fingerprint_fail);
    return 1;
}
