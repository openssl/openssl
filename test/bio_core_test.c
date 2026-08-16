/*
 * Copyright 2021-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <openssl/bio.h>
#include "testutil.h"

struct ossl_core_bio_st {
    int dummy;
    BIO *bio;
};

static int tst_bio_core_read_ex(OSSL_CORE_BIO *bio, char *data, size_t data_len,
    size_t *bytes_read)
{
    return BIO_read_ex(bio->bio, data, data_len, bytes_read);
}

static int tst_bio_core_write_ex(OSSL_CORE_BIO *bio, const char *data,
    size_t data_len, size_t *written)
{
    return BIO_write_ex(bio->bio, data, data_len, written);
}

static int tst_bio_core_gets(OSSL_CORE_BIO *bio, char *buf, int size)
{
    return BIO_gets(bio->bio, buf, size);
}

static int tst_bio_core_puts(OSSL_CORE_BIO *bio, const char *str)
{
    return BIO_puts(bio->bio, str);
}

static long tst_bio_core_ctrl(OSSL_CORE_BIO *bio, int cmd, long num, void *ptr)
{
    return BIO_ctrl(bio->bio, cmd, num, ptr);
}

static int tst_bio_core_up_ref(OSSL_CORE_BIO *bio)
{
    return BIO_up_ref(bio->bio);
}

static int tst_bio_core_free(OSSL_CORE_BIO *bio)
{
    return BIO_free(bio->bio);
}

static const OSSL_DISPATCH biocbs[] = {
    { OSSL_FUNC_BIO_READ_EX, (void (*)(void))tst_bio_core_read_ex },
    { OSSL_FUNC_BIO_WRITE_EX, (void (*)(void))tst_bio_core_write_ex },
    { OSSL_FUNC_BIO_GETS, (void (*)(void))tst_bio_core_gets },
    { OSSL_FUNC_BIO_PUTS, (void (*)(void))tst_bio_core_puts },
    { OSSL_FUNC_BIO_CTRL, (void (*)(void))tst_bio_core_ctrl },
    { OSSL_FUNC_BIO_UP_REF, (void (*)(void))tst_bio_core_up_ref },
    { OSSL_FUNC_BIO_FREE, (void (*)(void))tst_bio_core_free },
    OSSL_DISPATCH_END
};

static int call_bio_vsnprintf(char *buf, size_t n, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    ret = BIO_vsnprintf(buf, n, format, args);
    va_end(args);

    return ret;
}

static int test_bio_core(void)
{
    BIO *cbio = NULL, *cbiobad = NULL;
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new_from_dispatch(NULL, biocbs);
    int testresult = 0;
    OSSL_CORE_BIO corebio;
    const char *msg = "Hello world";
    char buf[80];

    corebio.bio = BIO_new(BIO_s_mem());
    if (!TEST_ptr(corebio.bio)
        || !TEST_ptr(libctx)
        /*
         * Attempting to create a corebio in a libctx that was not
         * created via OSSL_LIB_CTX_new_from_dispatch() should fail.
         */
        || !TEST_ptr_null((cbiobad = BIO_new_from_core_bio(NULL, &corebio)))
        || !TEST_ptr((cbio = BIO_new_from_core_bio(libctx, &corebio))))
        goto err;

    BIO_set_mem_eof_return(cbio, 0);
    if (!TEST_int_gt(BIO_puts(corebio.bio, msg), 0)
        /* Test a ctrl via BIO_eof */
        || !TEST_false(BIO_eof(cbio))
        || !TEST_int_gt(BIO_gets(cbio, buf, sizeof(buf)), 0)
        || !TEST_true(BIO_eof(cbio))
        || !TEST_str_eq(buf, msg))
        goto err;

    buf[0] = '\0';
    if (!TEST_int_gt(BIO_write(cbio, msg, (int)(strlen(msg) + 1)), 0)
        || !TEST_int_gt(BIO_read(cbio, buf, sizeof(buf)), 0)
        || !TEST_str_eq(buf, msg))
        goto err;

    testresult = 1;
err:
    BIO_free(cbiobad);
    BIO_free(cbio);
    BIO_free(corebio.bio);
    OSSL_LIB_CTX_free(libctx);
    return testresult;
}

static int test_bio_vprintf_boundary(void)
{
    BIO *bio = NULL;
    char *data;
    long len;
    int w;
    int testresult = 0;

    /*
     * At width 512, vsnprintf() reports 512 bytes excluding the NUL,
     * so BIO_vprintf() must use its realloc path.
     */
    for (w = 511; w <= 513; w++) {
        bio = BIO_new(BIO_s_mem());
        if (!TEST_ptr(bio))
            goto err;
        if (!TEST_int_eq(BIO_printf(bio, "%*d", w, 0), w))
            goto err;
        len = BIO_get_mem_data(bio, &data);
        if (!TEST_long_eq(len, w)
            || !TEST_char_eq(data[w - 1], '0')
            || !TEST_char_eq(data[0], ' '))
            goto err;
        BIO_free(bio);
        bio = NULL;
    }
    testresult = 1;
err:
    BIO_free(bio);
    return testresult;
}

static int test_bio_printf_c99_length_modifiers(void)
{
    static const char expected[] = "zu=12345 zd=-42 zx=3039 td=-7 ju=4294967338 jx=10000002a";
    static const char long_tail[] = "12345";
    BIO *bio = NULL;
    char buf[128];
    char *memdata = NULL;
    long memlen;
    size_t z = (size_t)12345;
    ossl_ssize_t zs = (ossl_ssize_t)-42;
    ptrdiff_t t = (ptrdiff_t)-7;
    ossl_uintmax_t j = (((ossl_uintmax_t)1) << 32) + 42;
    int expected_len = (int)strlen(expected);
    size_t long_tail_len = strlen(long_tail);
    int testresult = 0;

    if (!TEST_int_eq(BIO_snprintf(buf, sizeof(buf),
                         "zu=%zu zd=%zd zx=%zx td=%td ju=%ju jx=%jx",
                         z, zs, z, t, j, j),
            expected_len)
        || !TEST_str_eq(buf, expected))
        goto err;

    if (!TEST_int_eq(call_bio_vsnprintf(buf, sizeof(buf),
                         "zu=%zu zd=%zd zx=%zx td=%td ju=%ju jx=%jx",
                         z, zs, z, t, j, j),
            expected_len)
        || !TEST_str_eq(buf, expected))
        goto err;

    if (!TEST_ptr(bio = BIO_new(BIO_s_mem()))
        || !TEST_int_eq(BIO_printf(bio,
                            "zu=%zu zd=%zd zx=%zx td=%td ju=%ju jx=%jx",
                            z, zs, z, t, j, j),
            expected_len))
        goto err;

    memlen = BIO_get_mem_data(bio, &memdata);
    if (!TEST_long_eq(memlen, (long)strlen(expected))
        || !TEST_mem_eq(memdata, (size_t)memlen, expected, strlen(expected)))
        goto err;

    BIO_free(bio);
    bio = NULL;
    memdata = NULL;
    if (!TEST_ptr(bio = BIO_new(BIO_s_mem()))
        || !TEST_int_eq(BIO_printf(bio, "%600zu", z), 600))
        goto err;

    memlen = BIO_get_mem_data(bio, &memdata);
    if (!TEST_long_eq(memlen, 600)
        || !TEST_mem_eq(memdata + (size_t)memlen - long_tail_len,
            long_tail_len, long_tail, long_tail_len))
        goto err;

    if (!TEST_int_eq(BIO_snprintf(buf, 4, "%zu", z), -1))
        goto err;

    testresult = 1;
err:
    BIO_free(bio);
    return testresult;
}

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    ADD_TEST(test_bio_core);
    ADD_TEST(test_bio_vprintf_boundary);
    ADD_TEST(test_bio_printf_c99_length_modifiers);
    return 1;
}
