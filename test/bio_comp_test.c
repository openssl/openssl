/*
 * Copyright 2022-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/comp.h>

#include "testutil.h"
#include "testutil/output.h"
#include "testutil/tu_local.h"

#define COMPRESS 1
#define EXPAND 0

#define BUFFER_SIZE 32 * 1024
#define NUM_SIZES 4
static int sizes[NUM_SIZES] = { 64, 512, 2048, 16 * 1024 };

/* using global buffers */
static unsigned char *original = NULL;
static unsigned char *result = NULL;

/*
 * For compression:
 *   the write operation compresses
 *   the read operation decompresses
 */

static int do_bio_comp_test(const BIO_METHOD *meth, size_t size)
{
    BIO *bcomp = NULL;
    BIO *bmem = NULL;
    BIO *bexp = NULL;
    int osize;
    int rsize;
    int ret = 0;

    /* Compress */
    if (!TEST_ptr(meth))
        goto err;
    if (!TEST_ptr(bcomp = BIO_new(meth)))
        goto err;
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;
    BIO_push(bcomp, bmem);
    osize = BIO_write(bcomp, original, (int)size);
    if (!TEST_int_eq(osize, (int)size)
        || !TEST_true(BIO_flush(bcomp)))
        goto err;
    BIO_free(bcomp);
    bcomp = NULL;

    /* decompress */
    if (!TEST_ptr(bexp = BIO_new(meth)))
        goto err;
    BIO_push(bexp, bmem);
    rsize = BIO_read(bexp, result, (int)size);

    if (!TEST_int_eq((int)size, rsize)
        || !TEST_mem_eq(original, osize, result, rsize))
        goto err;

    ret = 1;
err:
    BIO_free(bexp);
    BIO_free(bcomp);
    BIO_free(bmem);
    return ret;
}

static int do_bio_comp(const BIO_METHOD *meth, int n)
{
    int i;
    int success = 0;
    int size = sizes[n % 4];
    int type = n / 4;

    original = OPENSSL_malloc(BUFFER_SIZE);
    result = OPENSSL_malloc(BUFFER_SIZE);

    if (!TEST_ptr(original) || !TEST_ptr(result))
        goto err;

    switch (type) {
    case 0:
        TEST_info("zeros of size %d\n", size);
        memset(original, 0, BUFFER_SIZE);
        break;
    case 1:
        TEST_info("ones of size %d\n", size);
        memset(original, 1, BUFFER_SIZE);
        break;
    case 2:
        TEST_info("sequential of size %d\n", size);
        for (i = 0; i < BUFFER_SIZE; i++)
            original[i] = i & 0xFF;
        break;
    case 3:
        TEST_info("random of size %d\n", size);
        if (!TEST_int_gt(RAND_bytes(original, BUFFER_SIZE), 0))
            goto err;
        break;
    default:
        goto err;
    }

    if (!TEST_true(do_bio_comp_test(meth, size)))
        goto err;
    success = 1;
err:
    OPENSSL_free(original);
    OPENSSL_free(result);
    return success;
}

#ifndef OPENSSL_NO_ZSTD
static int test_zstd(int n)
{
    return do_bio_comp(BIO_f_zstd(), n);
}
#endif
#ifndef OPENSSL_NO_BROTLI
static int test_brotli(int n)
{
    return do_bio_comp(BIO_f_brotli(), n);
}

static int test_brotli_wpending(void)
{
    BIO *bcomp = NULL;
    BIO *bmem = NULL;
    unsigned char buf[512];
    int ret = 0;

    memset(buf, 'A', sizeof(buf));
    if (!TEST_ptr(bcomp = BIO_new(BIO_f_brotli()))
        || !TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;
    BIO_push(bcomp, bmem);
    if (!TEST_int_eq(BIO_write(bcomp, buf, (int)sizeof(buf)), (int)sizeof(buf))
        || !TEST_true(BIO_flush(bcomp)))
        goto err;
    if (!TEST_int_eq(BIO_wpending(bcomp), 0))
        goto err;
    ret = 1;
err:
    BIO_free(bcomp);
    BIO_free(bmem);
    return ret;
}

static int test_brotli_wpending_nonzero(void)
{
    BIO *bcomp = NULL;
    BIO *bpair = NULL;
    BIO *bpeer = NULL;
    unsigned char buf[8192];
    int ret = 0;

    if (!TEST_int_gt(RAND_bytes(buf, sizeof(buf)), 0))
        goto err;
    if (!TEST_ptr(bcomp = BIO_new(BIO_f_brotli()))
        || !TEST_true(BIO_new_bio_pair(&bpair, 16, &bpeer, sizeof(buf))))
        goto err;
    BIO_push(bcomp, bpair);
    /* The small pair cannot drain the compressed output, so it stays pending */
    if (!TEST_int_gt(BIO_write(bcomp, buf, (int)sizeof(buf)), 0))
        goto err;
    if (!TEST_int_gt(BIO_wpending(bcomp), 1))
        goto err;
    ret = 1;
err:
    BIO_free(bcomp);
    BIO_free(bpair);
    BIO_free(bpeer);
    return ret;
}

static int test_brotli_pending(void)
{
    BIO *bcomp = NULL;
    BIO *bdec = NULL;
    BIO *bmem = NULL;
    unsigned char buf[8192];
    unsigned char slice[16];
    int ret = 0;

    /* Compressible: the decoder still holds output after avail_in hits zero */
    memset(buf, 'A', sizeof(buf));
    if (!TEST_ptr(bcomp = BIO_new(BIO_f_brotli()))
        || !TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;
    BIO_push(bcomp, bmem);
    if (!TEST_int_eq(BIO_write(bcomp, buf, (int)sizeof(buf)), (int)sizeof(buf))
        || !TEST_true(BIO_flush(bcomp)))
        goto err;
    BIO_free(bcomp);
    bcomp = NULL;

    if (!TEST_ptr(bdec = BIO_new(BIO_f_brotli())))
        goto err;
    BIO_push(bdec, bmem);
    if (!TEST_int_gt(BIO_read(bdec, slice, (int)sizeof(slice)), 0))
        goto err;
    /* Output is still buffered in the decoder, so pending must not be zero */
    if (!TEST_int_gt(BIO_pending(bdec), 0))
        goto err;
    /* Once drained, pending must report zero */
    while (BIO_read(bdec, slice, (int)sizeof(slice)) > 0)
        continue;
    if (!TEST_int_eq(BIO_pending(bdec), 0))
        goto err;
    ret = 1;
err:
    BIO_free(bcomp);
    BIO_free(bdec);
    BIO_free(bmem);
    return ret;
}
#endif
#ifndef OPENSSL_NO_ZLIB
static int test_zlib(int n)
{
    return do_bio_comp(BIO_f_zlib(), n);
}
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_ZLIB
    ADD_ALL_TESTS(test_zlib, NUM_SIZES * 4);
#endif
#ifndef OPENSSL_NO_BROTLI
    ADD_ALL_TESTS(test_brotli, NUM_SIZES * 4);
    ADD_TEST(test_brotli_wpending);
    ADD_TEST(test_brotli_wpending_nonzero);
    ADD_TEST(test_brotli_pending);
#endif
#ifndef OPENSSL_NO_ZSTD
    ADD_ALL_TESTS(test_zstd, NUM_SIZES * 4);
#endif
    return 1;
}
