/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bio.h>
#include "testutil.h"

#define TEST_FLAG_EOF_BEHAVIOUR 0x1000

static int bio_create(BIO *bio)
{
    BIO_set_init(bio, 1);
    return 1;
}

static int bio_destroy(BIO *bio)
{
    BIO_set_init(bio, 0);
    return 1;
}

/*
 * Test1 & Test2 read callback (old style):
 * returns 0 if TEST_FLAG_EOF_BEHAVIOUR is set, else -1.
 */
static int old_read_returns_0_or_minus1(BIO *bio, char *buf, int len)
{
    (void)buf;
    (void)len;
    return BIO_test_flags(bio, TEST_FLAG_EOF_BEHAVIOUR) ? 0 : -1;
}

/*
 * Test3 read_ex callback (new style):
 * does nothing, always returns 0, sets *readbytes to 0.
 */
static int new_read_ex_always_0(BIO *bio, char *buf, size_t len, size_t *readbytes)
{
    (void)bio;
    (void)buf;
    (void)len;
    if (readbytes != NULL)
        *readbytes = 0;
    return 0;
}

/* Test1 ctrl: does nothing */
static long ctrl_noop(BIO *bio, int cmd, long num, void *ptr)
{
    (void)bio;
    (void)cmd;
    (void)num;
    (void)ptr;
    return 0;
}

/* Test2 ctrl: BIO_CTRL_EOF always returns 1 */
static long ctrl_eof_always_1(BIO *bio, int cmd, long num, void *ptr)
{
    (void)bio;
    (void)num;
    (void)ptr;
    if (cmd == BIO_CTRL_EOF)
        return 1;
    return 0;
}

/* Test3 ctrl: BIO_CTRL_EOF returns 1 if TEST_FLAG_EOF_BEHAVIOUR is set */
static long ctrl_eof_depends_on_flag(BIO *bio, int cmd, long num, void *ptr)
{
    (void)num;
    (void)ptr;
    if (cmd == BIO_CTRL_EOF)
        return BIO_test_flags(bio, TEST_FLAG_EOF_BEHAVIOUR) ? 1 : 0;
    return 0;
}

static BIO_METHOD *make_meth_oldread(long (*ctrl)(BIO *, int, long, void *),
    const char *name)
{
    BIO_METHOD *meth = NULL;

    if (!TEST_ptr(meth = BIO_meth_new(BIO_TYPE_SOURCE_SINK, name)))
        goto err;
    if (!TEST_int_eq(BIO_meth_set_read(meth, old_read_returns_0_or_minus1), 1))
        goto err;
    if (!TEST_int_eq(BIO_meth_set_ctrl(meth, ctrl), 1))
        goto err;
    if (!TEST_int_eq(BIO_meth_set_create(meth, bio_create), 1))
        goto err;
    if (!TEST_int_eq(BIO_meth_set_destroy(meth, bio_destroy), 1))
        goto err;
    return meth;

err:
    BIO_meth_free(meth);
    return NULL;
}

static BIO_METHOD *make_meth_newreadex(long (*ctrl)(BIO *, int, long, void *),
    const char *name)
{
    BIO_METHOD *meth = NULL;

    if (!TEST_ptr(meth = BIO_meth_new(BIO_TYPE_SOURCE_SINK, name)))
        goto err;
    if (!TEST_int_eq(BIO_meth_set_read_ex(meth, new_read_ex_always_0), 1))
        goto err;
    if (!TEST_int_eq(BIO_meth_set_ctrl(meth, ctrl), 1))
        goto err;
    if (!TEST_int_eq(BIO_meth_set_create(meth, bio_create), 1))
        goto err;
    if (!TEST_int_eq(BIO_meth_set_destroy(meth, bio_destroy), 1))
        goto err;
    return meth;

err:
    BIO_meth_free(meth);
    return NULL;
}

static int run_subtest(const char *label, BIO_METHOD *meth,
    int set_flag, int use_read_ex,
    int exp_read_ret, int exp_eof_ret)
{
    BIO *bio = NULL;
    char b = 0;
    int r, eofr;
    size_t n;

    if (!TEST_ptr(bio = BIO_new(meth)))
        goto err;

    if (set_flag)
        BIO_set_flags(bio, TEST_FLAG_EOF_BEHAVIOUR);
    else
        BIO_clear_flags(bio, TEST_FLAG_EOF_BEHAVIOUR);

    if (use_read_ex) {
        r = BIO_read_ex(bio, &b, 1, &n);
        if (!TEST_int_eq(r, exp_read_ret)) {
            TEST_info("%s: BIO_read_ex ret=%d expected=%d", label, r, exp_read_ret);
            goto err;
        }
    } else {
        r = BIO_read(bio, &b, 1);
        if (!TEST_int_eq(r, exp_read_ret)) {
            TEST_info("%s: BIO_read ret=%d expected=%d", label, r, exp_read_ret);
            goto err;
        }
    }

    eofr = BIO_eof(bio);
    if (!TEST_int_eq(eofr, exp_eof_ret)) {
        TEST_info("%s: BIO_eof ret=%d expected=%d", label, eofr, exp_eof_ret);
        goto err;
    }

    BIO_free(bio);
    return 1;

err:
    BIO_free(bio);
    return 0;
}

static int old_style_read_without_eof_ctrl(void)
{
    int ok = 1;
    BIO_METHOD *meth = NULL;

    if (!TEST_ptr(meth = make_meth_oldread(ctrl_noop,
                      "Old-style read without eof ctrl")))
        return 0;

    ok &= run_subtest("BIO_read, eof", meth, 1, 0, 0, 1);
    ok &= run_subtest("BIO_read_ex, eof", meth, 1, 1, 0, 1);
    ok &= run_subtest("BIO_read, error", meth, 0, 0, -1, 0);
    ok &= run_subtest("BIO_read_ex, error", meth, 0, 1, 0, 0);

    BIO_meth_free(meth);
    return ok;
}

static int old_style_read_with_eof_ctrl(void)
{
    int ok = 1;
    BIO_METHOD *meth = NULL;

    if (!TEST_ptr(meth = make_meth_oldread(ctrl_eof_always_1,
                      "Old-stype read with eof ctrl")))
        return 0;

    ok &= run_subtest("BIO_read, eof", meth, 1, 0, 0, 1);
    ok &= run_subtest("BIO_read_ex, eof", meth, 1, 1, 0, 1);
    ok &= run_subtest("BIO_read, error", meth, 0, 0, -1, 1);
    ok &= run_subtest("BIO_read_ex, error", meth, 0, 1, 0, 1);

    BIO_meth_free(meth);
    return ok;
}

static int new_style_read_ex(void)
{
    int ok = 1;
    BIO_METHOD *meth = NULL;

    if (!TEST_ptr(meth = make_meth_newreadex(ctrl_eof_depends_on_flag,
                      "New-style read_ex")))
        return 0;

    ok &= run_subtest("BIO_read, eof", meth, 1, 0, 0, 1);
    ok &= run_subtest("BIO_read_ex, eof", meth, 1, 1, 0, 1);
    ok &= run_subtest("BIO_read, error", meth, 0, 0, -1, 0);
    ok &= run_subtest("BIO_read_ex, error", meth, 0, 1, 0, 0);

    BIO_meth_free(meth);
    return ok;
}

int setup_tests(void)
{
    ADD_TEST(old_style_read_without_eof_ctrl);
    ADD_TEST(old_style_read_with_eof_ctrl);
    ADD_TEST(new_style_read_ex);
    return 1;
}
