/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bio.h>
#include <openssl/ts.h>

#include "testutil.h"

static const char *response_file;
static const char *data_file;
static BIO_METHOD *terminal_bio_method;

struct terminal_bio_data {
    BIO *source;
    int error_at_eof;
};

static int terminal_bio_read(BIO *bio, char *out, int outl)
{
    struct terminal_bio_data *data = BIO_get_data(bio);
    int ret = BIO_read(data->source, out, outl);

    if (ret == 0 && data->error_at_eof)
        return -1;
    return ret;
}

static int terminal_bio_destroy(BIO *bio)
{
    struct terminal_bio_data *data;

    if (bio == NULL)
        return 0;
    data = BIO_get_data(bio);
    if (data != NULL) {
        BIO_free(data->source);
        OPENSSL_free(data);
    }
    BIO_set_data(bio, NULL);
    BIO_set_init(bio, 0);
    return 1;
}

static BIO *terminal_bio_new(int error_at_eof)
{
    struct terminal_bio_data *data = NULL;
    BIO *bio = NULL;

    if ((data = OPENSSL_zalloc(sizeof(*data))) == NULL
        || (data->source = BIO_new_file(data_file, "rb")) == NULL
        || (bio = BIO_new(terminal_bio_method)) == NULL)
        goto err;

    data->error_at_eof = error_at_eof;
    BIO_set_data(bio, data);
    BIO_set_init(bio, 1);
    return bio;

err:
    BIO_free(bio);
    if (data != NULL) {
        BIO_free(data->source);
        OPENSSL_free(data);
    }
    return NULL;
}

static int verify_data(TS_RESP *response, int error_at_eof)
{
    TS_VERIFY_CTX *ctx = NULL;
    BIO *data = NULL;
    int ret = -1;

    if (!TEST_ptr(ctx = TS_VERIFY_CTX_new())
        || !TEST_ptr(data = terminal_bio_new(error_at_eof))
        || !TEST_int_eq(TS_VERIFY_CTX_set_flags(ctx, TS_VFY_DATA), TS_VFY_DATA)
        || !TEST_true(TS_VERIFY_CTX_set0_data(ctx, data)))
        goto err;
    data = NULL;
    ret = TS_RESP_verify_response(ctx, response);

err:
    BIO_free(data);
    TS_VERIFY_CTX_free(ctx);
    return ret;
}

static int test_read_error_is_not_eof(void)
{
    BIO *bio = NULL;
    TS_RESP *response = NULL;
    int ret = 0;

    if (!TEST_ptr(bio = BIO_new_file(response_file, "rb"))
        || !TEST_ptr(response = d2i_TS_RESP_bio(bio, NULL)))
        goto err;

    ret = TEST_true(verify_data(response, 0))
        && TEST_false(verify_data(response, 1));

err:
    TS_RESP_free(response);
    BIO_free(bio);
    return ret;
}

OPT_TEST_DECLARE_USAGE("response-file data-file\n")

int setup_tests(void)
{
    if (!test_skip_common_options()
        || !TEST_ptr(response_file = test_get_argument(0))
        || !TEST_ptr(data_file = test_get_argument(1)))
        return 0;

    if (!TEST_ptr(terminal_bio_method = BIO_meth_new(BIO_TYPE_SOURCE_SINK,
                      "terminal read test BIO"))
        || !TEST_true(BIO_meth_set_read(terminal_bio_method,
            terminal_bio_read))
        || !TEST_true(BIO_meth_set_destroy(terminal_bio_method,
            terminal_bio_destroy)))
        return 0;

    ADD_TEST(test_read_error_is_not_eof);
    return 1;
}

void cleanup_tests(void)
{
    BIO_meth_free(terminal_bio_method);
}
