/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include "testutil.h"

static int evp_md_null_param_test(void)
{
    int ret;
    EVP_MD *md = NULL;
    const EVP_MD *omd = EVP_sha256();
    OSSL_PARAM params[1] = { OSSL_PARAM_END };

    EVP_MD_free(md);
    ret = TEST_int_eq(EVP_MD_get_type(md), NID_undef)
          && TEST_int_eq(EVP_MD_get_pkey_type(md), NID_undef)
          && TEST_ptr_null(EVP_MD_get0_name(md))
          && TEST_ptr_null(EVP_MD_get0_description(md))
          && TEST_false(EVP_MD_is_a(md, "SHA256"))
          && TEST_false(EVP_MD_is_a(omd, NULL))
          && TEST_false(EVP_MD_names_do_all(md, NULL, NULL))
          && TEST_ptr_null(EVP_MD_get0_provider(md))
          && TEST_int_eq(EVP_MD_get_size(md), -1)
          && TEST_int_eq(EVP_MD_get_block_size(md), -1)
          && TEST_int_eq(EVP_MD_get_flags(md), 0)
          && TEST_ptr_null(EVP_MD_gettable_params(md))
          && TEST_int_eq(EVP_MD_get_params(md, params), 0)
          && TEST_ptr_null(EVP_MD_settable_ctx_params(md))
          && TEST_ptr_null(EVP_MD_gettable_ctx_params(md))
          && TEST_int_eq(EVP_MD_up_ref(md), 0);
    return ret;
}

static int evp_md_ctx_null_param_test(void)
{
    int ret, flags = 1;
    EVP_MD_CTX *ctx = NULL, *octx = NULL;
    OSSL_PARAM params[1] = { OSSL_PARAM_END };
    const EVP_MD *md = EVP_sha256();
    unsigned char buf[1] = { 0 };
    unsigned int len = 0;

    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_set_pkey_ctx(ctx, NULL);
    EVP_MD_CTX_set_flags(ctx, flags);
    EVP_MD_CTX_clear_flags(ctx, flags);

    ret = TEST_ptr(octx = EVP_MD_CTX_new())
          && TEST_int_eq(EVP_MD_CTX_reset(ctx), 1)
          && TEST_ptr_null(EVP_MD_CTX_get0_md(ctx))
          && TEST_ptr_null(EVP_MD_CTX_get1_md(ctx))
          && TEST_ptr_null(EVP_MD_CTX_get_pkey_ctx(ctx))
          && TEST_ptr_null(EVP_MD_CTX_get0_md_data(ctx))
          && TEST_ptr_null(EVP_MD_CTX_settable_params(ctx))
          && TEST_ptr_null(EVP_MD_CTX_gettable_params(ctx))
          && TEST_int_eq(EVP_MD_CTX_set_params(ctx, params), 0)
          && TEST_int_eq(EVP_MD_CTX_get_params(ctx, params), 0)
          && TEST_int_eq(EVP_MD_CTX_ctrl(ctx, 0, 0, NULL), 0)
          && TEST_int_eq(EVP_MD_CTX_copy_ex(ctx, octx), 0)
          && TEST_int_eq(EVP_MD_CTX_copy_ex(octx, ctx), 0)
          && TEST_int_eq(EVP_MD_CTX_copy(ctx, octx), 0)
          && TEST_int_eq(EVP_MD_CTX_copy(octx, ctx), 0)
          && TEST_int_eq(EVP_MD_CTX_test_flags(ctx, flags), 0)
          && TEST_int_eq(EVP_DigestInit_ex2(ctx, md, NULL), 0)
          && TEST_int_eq(EVP_DigestInit_ex(ctx, md, NULL), 0)
          && TEST_int_eq(EVP_DigestInit(ctx, md), 0)
          && TEST_int_eq(EVP_DigestUpdate(ctx, buf, sizeof(buf)), 0)
          && TEST_int_eq(EVP_DigestFinal_ex(ctx, buf, &len), 0)
          && TEST_int_eq(EVP_DigestFinal(ctx, buf, &len), 0)
          && TEST_int_eq(EVP_DigestFinalXOF(ctx, buf, sizeof(buf)), 0);
    EVP_MD_CTX_free(octx);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(evp_md_null_param_test);
    ADD_TEST(evp_md_ctx_null_param_test);
    return 1;
}
