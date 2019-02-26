/*
 * Copyright 2018-2019 The OpenSSL Project Authors. All Rights Reserved.
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
    const char *str = "BIO test\n";
    char buf[100];

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
        goto finish;
    bufmem.length = strlen(str) + 1;
    bufmem.data = (char *) str;
    bufmem.max = bufmem.length;
    BIO_set_mem_buf(bio, &bufmem, BIO_NOCLOSE);
    BIO_set_flags(bio, BIO_FLAGS_MEM_RDONLY);

    if (BIO_read(bio, buf, sizeof(buf)) <= 0)
	goto finish;

    ok = strcmp(buf, str) == 0;

finish:
    BIO_free(bio);
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
    return 1;
}
