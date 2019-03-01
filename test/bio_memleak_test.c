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
#include <openssl/buffer.h>
#include <openssl/bio.h>

#include "testutil.h"

static int test_bio_memleak(void)
{
    int ok = 0;
    BIO *bio;
    BUF_MEM bufmem;
    static const char str[] = "BIO test\n";
    char buf[100];

    bio = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bio))
        goto finish;
    bufmem.length = sizeof(str);
    bufmem.data = (char *) str;
    bufmem.max = bufmem.length;
    BIO_set_mem_buf(bio, &bufmem, BIO_NOCLOSE);
    BIO_set_flags(bio, BIO_FLAGS_MEM_RDONLY);
    if (!TEST_int_eq(BIO_read(bio, buf, sizeof(buf)), sizeof(str)))
        goto finish;
    if (!TEST_mem_eq(buf, sizeof(str), str, sizeof(str)))
        goto finish;
    ok = 1;

finish:
    BIO_free(bio);
    return ok;
}

static int test_bio_get_mem(void)
{
    int ok = 0;
    BIO *bio = NULL;
    BUF_MEM *bufmem = NULL;

    bio = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bio))
        goto finish;
    if (!TEST_int_eq(BIO_puts(bio, "Hello World\n"), 12))
        goto finish;
    BIO_get_mem_ptr(bio, &bufmem);
    if (!TEST_ptr(bufmem))
        goto finish;
    if (!TEST_int_gt(BIO_set_close(bio, BIO_NOCLOSE), 0))
        goto finish;
    BIO_free(bio);
    bio = NULL;
    if (!TEST_mem_eq(bufmem->data, bufmem->length, "Hello World\n", 12))
        goto finish;
    ok = 1;

finish:
    BIO_free(bio);
    BUF_MEM_free(bufmem);
    return ok;
}

int global_init(void)
{
    CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    return 1;
}

int setup_tests(void)
{
    ADD_TEST(test_bio_memleak);
    ADD_TEST(test_bio_get_mem);
    return 1;
}
