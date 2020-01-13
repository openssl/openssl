/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Opentls license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/core_numbers.h>
#include <opentls/types.h>

typedef struct self_test_post_params_st {
    /* FIPS module integrity check parameters */
    const char *module_filename;            /* Module file to perform MAC on */
    const char *module_checksum_data;       /* Expected module MAC integrity */

    /* Used for KAT install indicator integrity check */
    const char *indicator_version;          /* version - for future proofing */
    const char *indicator_data;             /* data to perform MAC on */
    const char *indicator_checksum_data;    /* Expected MAC integrity value */

    /* BIO callbacks supplied to the FIPS provider */
    Otls_BIO_new_file_fn *bio_new_file_cb;
    Otls_BIO_new_membuf_fn *bio_new_buffer_cb;
    Otls_BIO_read_ex_fn *bio_read_ex_cb;
    Otls_BIO_free_fn *bio_free_cb;
    OPENtls_CTX *libctx;

} SELF_TEST_POST_PARAMS;

int SELF_TEST_post(SELF_TEST_POST_PARAMS *st, int on_demand_test);
