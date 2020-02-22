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
#include <openssl/self_test.h>

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
    OSSL_CALLBACK *event_cb;
    void *event_cb_arg;
    OPENSSL_CTX *libctx;

} SELF_TEST_POST_PARAMS;

typedef struct st_event_st
{
    /* local state variables */
    const char *phase;
    const char *type;
    const char *desc;
    OSSL_CALLBACK *cb;

    /* callback related variables used to pass the state back to the user */
    OSSL_PARAM params[4];
    void *cb_arg;

} OSSL_ST_EVENT;

int SELF_TEST_post(SELF_TEST_POST_PARAMS *st, int on_demand_test);
int SELF_TEST_kats(OSSL_ST_EVENT *event, OPENSSL_CTX *libctx);

void SELF_TEST_EVENT_init(OSSL_ST_EVENT *ev, OSSL_CALLBACK *cb, void *cbarg);
void SELF_TEST_EVENT_onbegin(OSSL_ST_EVENT *ev, const char *type,
                             const char *desc);
void SELF_TEST_EVENT_onend(OSSL_ST_EVENT *ev, int ret);
void SELF_TEST_EVENT_oncorrupt_byte(OSSL_ST_EVENT *ev, unsigned char *bytes);
