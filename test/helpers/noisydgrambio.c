/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bio.h>
#include "quictestlib.h"
#include "../testutil.h"

struct noisy_dgram_st {
    size_t this_dgram;
};

static int noisy_dgram_read(BIO *bio, char *out, int outl)
{
    /* We don't support this - not needed anyway */
    return -1;
}

static int noisy_dgram_write(BIO *bio, const char *in, int inl)
{
    /* We don't support this - not needed anyway */
    return -1;
}

static long noisy_dgram_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    long ret;
    BIO *next = BIO_next(bio);

    if (next == NULL)
        return 0;

    switch (cmd) {
    case BIO_CTRL_DUP:
        ret = 0L;
        break;
    default:
        ret = BIO_ctrl(next, cmd, num, ptr);
        break;
    }
    return ret;
}

static int noisy_dgram_gets(BIO *bio, char *buf, int size)
{
    /* We don't support this - not needed anyway */
    return -1;
}

static int noisy_dgram_puts(BIO *bio, const char *str)
{
    /* We don't support this - not needed anyway */
    return -1;
}

static int noisy_dgram_sendmmsg(BIO *bio, BIO_MSG *msg, size_t stride,
                                size_t num_msg, uint64_t flags,
                                size_t *msgs_processed)
{
    BIO *next = BIO_next(bio);

    if (next == NULL)
        return 0;

    /*
     * We only introduce noise when receiving messages. We just pass this on
     * to the underlying BIO.
     */
    return BIO_sendmmsg(next, msg, stride, num_msg, flags, msgs_processed);
}

static int should_drop(BIO *bio)
{
    struct noisy_dgram_st *data = BIO_get_data(bio);

    if (data == NULL)
        return 0;

    /*
     * Drop datagram 1 for now.
     * TODO(QUIC): Provide more control over this behaviour.
     */
    if (data->this_dgram == 1)
        return 1;

    return 0;
}

/* There isn't a public function to do BIO_ADDR_copy() so we create one */
static int bio_addr_copy(BIO_ADDR *dst, BIO_ADDR *src)
{
    size_t len;
    void *data = NULL;
    int res = 0;
    int family;

    if (src == NULL || dst == NULL)
        return 0;

    family = BIO_ADDR_family(src);
    if (family == AF_UNSPEC) {
        BIO_ADDR_clear(dst);
        return 1;
    }

    if (!BIO_ADDR_rawaddress(src, NULL, &len))
        return 0;

    if (len > 0) {
        data = OPENSSL_malloc(len);
        if (!TEST_ptr(data))
            return 0;
    }

    if (!BIO_ADDR_rawaddress(src, data, &len))
        goto err;

    if (!BIO_ADDR_rawmake(src, family, data, len, BIO_ADDR_rawport(src)))
        goto err;

    res = 1;
 err:
    OPENSSL_free(data);
    return res;
}

static int noisy_dgram_recvmmsg(BIO *bio, BIO_MSG *msg, size_t stride,
                                size_t num_msg, uint64_t flags,
                                size_t *msgs_processed)
{
    BIO *next = BIO_next(bio);
    size_t i, data_len = 0, drop_cnt = 0;
    BIO_MSG *src, *dst;
    struct noisy_dgram_st *data;

    if (!TEST_ptr(next))
        return 0;

    data = BIO_get_data(bio);
    if (!TEST_ptr(data))
        return 0;

    /*
     * For simplicity we assume that all elements in the msg array have the
     * same data_len. They are not required to by the API, but it would be quite
     * strange for that not to be the case - and our code that calls
     * BIO_recvmmsg does do this (which is all that is important for this test
     * code). We test the invariant here.
     */
    for (i = 0; i < num_msg; i++) {
        if (i == 0)
            data_len = msg[i].data_len;
        else if (!TEST_size_t_eq(msg[i].data_len, data_len))
            return 0;
    }

    if (!BIO_recvmmsg(next, msg, stride, num_msg, flags, msgs_processed))
        return 0;

    /* Drop any messages */
    for (i = 0, src = msg, dst = msg;
         i < *msgs_processed;
         i++, src++, data->this_dgram++) {
        if (should_drop(bio)) {
            drop_cnt++;
            continue;
        }

        if (src != dst) {
            /* Copy the src BIO_MSG to the dst BIO_MSG */
            memcpy(dst->data, src->data, src->data_len);
            dst->data_len = src->data_len;
            dst->flags = src->flags;
            if (src->local != NULL
                    && !TEST_true(bio_addr_copy(dst->local, src->local)))
                return 0;
            if (!TEST_true(bio_addr_copy(dst->peer, src->peer)))
                return 0;
        }

        dst++;
    }

    *msgs_processed -= drop_cnt;

    if (*msgs_processed == 0) {
        ERR_raise(ERR_LIB_BIO, BIO_R_NON_FATAL);
        return 0;
    }

    return 1;
}

static int noisy_dgram_new(BIO *bio)
{
    struct noisy_dgram_st *data = OPENSSL_zalloc(sizeof(*data));

    if (!TEST_ptr(data))
        return 0;

    BIO_set_data(bio, data);
    BIO_set_init(bio, 1);

    return 1;
}

static int noisy_dgram_free(BIO *bio)
{
    OPENSSL_free(BIO_get_data(bio));
    BIO_set_data(bio, NULL);
    BIO_set_init(bio, 0);

    return 1;
}

/* Choose a sufficiently large type likely to be unused for this custom BIO */
#define BIO_TYPE_NOISY_DGRAM_FILTER  (0x80 | BIO_TYPE_FILTER)

static BIO_METHOD *method_noisy_dgram = NULL;

/* Note: Not thread safe! */
const BIO_METHOD *bio_f_noisy_dgram_filter(void)
{
    if (method_noisy_dgram == NULL) {
        method_noisy_dgram = BIO_meth_new(BIO_TYPE_NOISY_DGRAM_FILTER,
                                          "Nosiy datagram filter");
        if (method_noisy_dgram == NULL
            || !BIO_meth_set_write(method_noisy_dgram, noisy_dgram_write)
            || !BIO_meth_set_read(method_noisy_dgram, noisy_dgram_read)
            || !BIO_meth_set_puts(method_noisy_dgram, noisy_dgram_puts)
            || !BIO_meth_set_gets(method_noisy_dgram, noisy_dgram_gets)
            || !BIO_meth_set_ctrl(method_noisy_dgram, noisy_dgram_ctrl)
            || !BIO_meth_set_sendmmsg(method_noisy_dgram, noisy_dgram_sendmmsg)
            || !BIO_meth_set_recvmmsg(method_noisy_dgram, noisy_dgram_recvmmsg)
            || !BIO_meth_set_create(method_noisy_dgram, noisy_dgram_new)
            || !BIO_meth_set_destroy(method_noisy_dgram, noisy_dgram_free))
            return NULL;
    }
    return method_noisy_dgram;
}

void bio_f_noisy_dgram_filter_free(void)
{
    BIO_meth_free(method_noisy_dgram);
}
