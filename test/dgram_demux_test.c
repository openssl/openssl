/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>
#include <openssl/bio.h>
#include "internal/dgram_demux.h"
#include "testutil.h"

/* The demuxer's MTU before any BIO or caller has changed it. */
#define DEFAULT_MTU 1500
/* The largest MTU the demuxer takes from a BIO. */
#define MAX_MTU 65535

/*
 * A datagram BIO which answers the controls the demuxer uses with the values
 * it is given, and which records what the demuxer asks of it when it receives.
 */
typedef struct test_bio_st {
    /* Returned for BIO_CTRL_DGRAM_GET_MTU. */
    long mtu_ret;
    /* Returned for the controls which query and enable the local address. */
    long local_ret;
    /* Length of the first receive buffer the demuxer offered. */
    size_t buf_len;
    /* Whether the demuxer asked for the local address. */
    int local_requested;
    /* Number of datagrams passed to the handler. */
    int num_handled;
    DGRAM_DEMUX *demux;
} TEST_BIO;

static BIO_METHOD *meth_ctrl, *meth_no_ctrl;

static long test_bio_ctrl(BIO *bio, int cmd, long larg, void *parg)
{
    TEST_BIO *tb = BIO_get_data(bio);

    switch (cmd) {
    case BIO_CTRL_DGRAM_GET_MTU:
        return tb->mtu_ret;
    case BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP:
    case BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE:
        return tb->local_ret;
    default:
        return 0;
    }
}

/* Delivers a single one-byte datagram per call. */
static int test_bio_recvmmsg(BIO *bio, BIO_MSG *msg, size_t stride,
    size_t num_msg, uint64_t flags,
    size_t *msgs_processed)
{
    TEST_BIO *tb = BIO_get_data(bio);

    *msgs_processed = 0;
    if (num_msg == 0)
        return 1;

    tb->buf_len = msg[0].data_len;
    tb->local_requested = msg[0].local != NULL;
    if (msg[0].data_len == 0)
        return 0;

    *(unsigned char *)msg[0].data = 0x42;
    msg[0].data_len = 1;
    *msgs_processed = 1;
    return 1;
}

static void test_handler(DGRAM_URXE *e, void *arg)
{
    TEST_BIO *tb = arg;

    ++tb->num_handled;
    ossl_dgram_demux_release_urxe(tb->demux, e);
}

static BIO *test_bio_new(const BIO_METHOD *meth, TEST_BIO *tb)
{
    BIO *bio = BIO_new(meth);

    if (bio == NULL)
        return NULL;

    BIO_set_data(bio, tb);
    BIO_set_init(bio, 1);
    return bio;
}

static const struct {
    int have_ctrl;
    long mtu_ret, local_ret;
    size_t expect_mtu;
    int expect_local;
} bio_cases[] = {
    /* No ctrl method at all; BIO_ctrl() returns -2. */
    { 0, 0, 0, DEFAULT_MTU, 0 },
    /* Controls the BIO does not implement. */
    { 1, -1, -1, DEFAULT_MTU, 0 },
    { 1, -2, -2, DEFAULT_MTU, 0 },
    { 1, LONG_MIN, INT_MIN, DEFAULT_MTU, 0 },
    { 1, 0, 0, DEFAULT_MTU, 0 },
    /* An MTU below the minimum is not used. */
    { 1, 1, 1, DEFAULT_MTU, 1 },
    { 1, 1199, 1, DEFAULT_MTU, 1 },
    /* An MTU in range is used as reported. */
    { 1, 1200, 1, 1200, 1 },
    { 1, 9000, 0, 9000, 0 },
    { 1, MAX_MTU, -1, MAX_MTU, 0 },
    /* A larger MTU is limited to the largest datagram. */
    { 1, MAX_MTU + 1, 1, MAX_MTU, 1 },
    { 1, INT_MAX, 1, MAX_MTU, 1 },
    { 1, LONG_MAX, 1, MAX_MTU, 1 },
};

/*
 * The MTU a BIO reports sizes every receive buffer, so a BIO which cannot
 * report one must leave the demuxer's MTU alone, however it says so.
 */
static int test_bio_mtu(int idx)
{
    int testresult = 0;
    TEST_BIO tb = { 0 };
    const BIO_METHOD *meth;
    BIO *bio = NULL;
    DGRAM_DEMUX *demux = NULL;

    meth = bio_cases[idx].have_ctrl ? meth_ctrl : meth_no_ctrl;
    tb.mtu_ret = bio_cases[idx].mtu_ret;
    tb.local_ret = bio_cases[idx].local_ret;

    if (!TEST_ptr(bio = test_bio_new(meth, &tb))
        || !TEST_ptr(demux = ossl_dgram_demux_new(bio, 0, NULL, NULL)))
        goto err;

    /*
     * Check this before receiving anything: a pump allocates a batch of
     * buffers of this size.
     */
    if (!TEST_size_t_eq(ossl_dgram_demux_get_mtu(demux),
            bio_cases[idx].expect_mtu))
        goto err;

    tb.demux = demux;
    ossl_dgram_demux_set_default_handler(demux, test_handler, &tb);

    if (!TEST_int_eq(ossl_dgram_demux_pump(demux), DGRAM_DEMUX_PUMP_RES_OK)
        || !TEST_int_eq(tb.num_handled, 1)
        || !TEST_size_t_eq(tb.buf_len, bio_cases[idx].expect_mtu)
        || !TEST_int_eq(tb.local_requested, bio_cases[idx].expect_local))
        goto err;

    testresult = 1;
err:
    ossl_dgram_demux_free(demux);
    BIO_free(bio);
    return testresult;
}

/* A BIO which reports no MTU leaves the last known one in place. */
static int test_bio_keeps_last_mtu(void)
{
    int testresult = 0;
    TEST_BIO tb_none = { 0 }, tb_jumbo = { 0 };
    BIO *bio_none = NULL, *bio_no_ctrl = NULL, *bio_jumbo = NULL;
    DGRAM_DEMUX *demux = NULL;

    tb_none.mtu_ret = -1;
    tb_jumbo.mtu_ret = 9000;

    if (!TEST_ptr(bio_none = test_bio_new(meth_ctrl, &tb_none))
        || !TEST_ptr(bio_no_ctrl = test_bio_new(meth_no_ctrl, &tb_none))
        || !TEST_ptr(bio_jumbo = test_bio_new(meth_ctrl, &tb_jumbo))
        || !TEST_ptr(demux = ossl_dgram_demux_new(NULL, 0, NULL, NULL)))
        goto err;

    if (!TEST_size_t_eq(ossl_dgram_demux_get_mtu(demux), DEFAULT_MTU)
        || !TEST_true(ossl_dgram_demux_set_mtu(demux, 2000))
        || !TEST_size_t_eq(ossl_dgram_demux_get_mtu(demux), 2000))
        goto err;

    ossl_dgram_demux_set_bio(demux, bio_none);
    if (!TEST_size_t_eq(ossl_dgram_demux_get_mtu(demux), 2000))
        goto err;

    ossl_dgram_demux_set_bio(demux, bio_no_ctrl);
    if (!TEST_size_t_eq(ossl_dgram_demux_get_mtu(demux), 2000))
        goto err;

    ossl_dgram_demux_set_bio(demux, bio_jumbo);
    if (!TEST_size_t_eq(ossl_dgram_demux_get_mtu(demux), 9000))
        goto err;

    ossl_dgram_demux_set_bio(demux, bio_none);
    if (!TEST_size_t_eq(ossl_dgram_demux_get_mtu(demux), 9000))
        goto err;

    ossl_dgram_demux_set_bio(demux, NULL);
    if (!TEST_size_t_eq(ossl_dgram_demux_get_mtu(demux), 9000))
        goto err;

    testresult = 1;
err:
    ossl_dgram_demux_free(demux);
    BIO_free(bio_none);
    BIO_free(bio_no_ctrl);
    BIO_free(bio_jumbo);
    return testresult;
}

int setup_tests(void)
{
    int type = BIO_get_new_index();

    if (!TEST_int_ne(type, -1))
        return 0;

    type |= BIO_TYPE_SOURCE_SINK;
    if (!TEST_ptr(meth_ctrl = BIO_meth_new(type, "demux test"))
        || !TEST_ptr(meth_no_ctrl = BIO_meth_new(type, "demux test, no ctrl"))
        || !TEST_true(BIO_meth_set_ctrl(meth_ctrl, test_bio_ctrl))
        || !TEST_true(BIO_meth_set_recvmmsg(meth_ctrl, test_bio_recvmmsg))
        || !TEST_true(BIO_meth_set_recvmmsg(meth_no_ctrl, test_bio_recvmmsg)))
        return 0;

    ADD_ALL_TESTS(test_bio_mtu, OSSL_NELEM(bio_cases));
    ADD_TEST(test_bio_keeps_last_mtu);
    return 1;
}

void cleanup_tests(void)
{
    BIO_meth_free(meth_ctrl);
    BIO_meth_free(meth_no_ctrl);
}
