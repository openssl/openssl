/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_numbers.h>
#include <openssl/types.h>

typedef struct self_test_post_params_st {
    /* FIPS module integrity check parameters */
    const char *module_filename;            /* Module file to perform MAC on */
    const char *module_checksum_data;       /* Expected module MAC integrity */

    /* Used for KAT install indicator integrity check */
    const char *indicator_version;          /* version - for future proofing */
    const char *indicator_data;             /* data to perform MAC on */
    const char *indicator_checksum_data;    /* Expected MAC integrity value */

    /* BIO callbacks supplied to the FIPS provider */
    OSSL_BIO_new_file_fn *bio_new_file_cb;
    OSSL_BIO_new_membuf_fn *bio_new_buffer_cb;
    OSSL_BIO_read_ex_fn *bio_read_ex_cb;
    OSSL_BIO_free_fn *bio_free_cb;
    OPENSSL_CTX *libctx;

} SELF_TEST_POST_PARAMS;

int SELF_TEST_post(SELF_TEST_POST_PARAMS *st);
