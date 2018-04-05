/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>

#include "testutil.h"

#define MAXCOUNT 5
static int         my_param_count;
static BIO        *my_param_b[MAXCOUNT];
static int         my_param_oper[MAXCOUNT];
static const char *my_param_argp[MAXCOUNT];
static int         my_param_argi[MAXCOUNT];
static long        my_param_argl[MAXCOUNT];
static long        my_param_ret[MAXCOUNT];

static long my_bio_callback(BIO *b, int oper, const char *argp, int argi,
                            long argl, long ret)
{
    if (my_param_count >= MAXCOUNT)
        return -1;
    my_param_b[my_param_count]    = b;
    my_param_oper[my_param_count] = oper;
    my_param_argp[my_param_count] = argp;
    my_param_argi[my_param_count] = argi;
    my_param_argl[my_param_count] = argl;
    my_param_ret[my_param_count]  = ret;
    my_param_count++;
    return ret;
}

static int test_bio_callback(void)
{
    int ok = 0;
    BIO *bio;
    int i;
    char *test1 = "test";
    char *test2 = "hello";

    my_param_count = 0;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
        goto err;

    BIO_set_callback(bio, my_bio_callback);
    i = BIO_write(bio, test1, 4);
    if (!TEST_int_eq(i, 4)
            || !TEST_int_eq(my_param_count, 2)
            || !TEST_ptr_eq(my_param_b[0], bio)
            || !TEST_int_eq(my_param_oper[0], BIO_CB_WRITE)
            || !TEST_ptr_eq(my_param_argp[0], test1)
            || !TEST_int_eq(my_param_argi[0], 4)
            || !TEST_long_eq(my_param_argl[0], 0L)
            || !TEST_long_eq(my_param_ret[0], 1L)
            || !TEST_ptr_eq(my_param_b[1], bio)
            || !TEST_int_eq(my_param_oper[1], BIO_CB_WRITE | BIO_CB_RETURN)
            || !TEST_ptr_eq(my_param_argp[1], test1)
            || !TEST_int_eq(my_param_argi[1], 4)
            || !TEST_long_eq(my_param_argl[1], 0L)
            || !TEST_long_eq(my_param_ret[1], 4L))
        goto err;

    i = BIO_puts(bio, test2);
    if (!TEST_int_eq(i, 5)
            || !TEST_int_eq(my_param_count, 4)
            || !TEST_ptr_eq(my_param_b[2], bio)
            || !TEST_int_eq(my_param_oper[2], BIO_CB_PUTS)
            || !TEST_ptr_eq(my_param_argp[2], test2)
            || !TEST_int_eq(my_param_argi[2], 0)
            || !TEST_long_eq(my_param_argl[2], 0L)
            || !TEST_long_eq(my_param_ret[2], 1L)
            || !TEST_ptr_eq(my_param_b[3], bio)
            || !TEST_int_eq(my_param_oper[3], BIO_CB_PUTS | BIO_CB_RETURN)
            || !TEST_ptr_eq(my_param_argp[3], test2)
            || !TEST_int_eq(my_param_argi[3], 0)
            || !TEST_long_eq(my_param_argl[3], 0L)
            || !TEST_long_eq(my_param_ret[3], 5L))
        goto err;

    i = BIO_free(bio);

    if (!TEST_int_eq(i, 1)
            || !TEST_int_eq(my_param_count, 5)
            || !TEST_ptr_eq(my_param_b[4], bio)
            || !TEST_int_eq(my_param_oper[4], BIO_CB_FREE)
            || !TEST_ptr_eq(my_param_argp[4], NULL)
            || !TEST_int_eq(my_param_argi[4], 0)
            || !TEST_long_eq(my_param_argl[4], 0L)
            || !TEST_long_eq(my_param_ret[4], 1L))
        goto finish;

    ok = 1;
    goto finish;

err:
    BIO_free(bio);

finish:
    /* This helps finding memory leaks with ASAN */
    memset(my_param_b, 0, sizeof(my_param_b));
    memset(my_param_argp, 0, sizeof(my_param_argp));
    return ok;
}

int setup_tests(void)
{
    ADD_TEST(test_bio_callback);
    return 1;
}
