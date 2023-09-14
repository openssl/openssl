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

static int noisy_dgram_recvmmsg(BIO *bio, BIO_MSG *msg, size_t stride,
                                size_t num_msg, uint64_t flags,
                                size_t *msgs_processed)
{
    BIO *next = BIO_next(bio);

    if (next == NULL)
        return 0;

    /*
     * We will introduce noise here. None implemented yet.
     */
    return BIO_recvmmsg(next, msg, stride, num_msg, flags, msgs_processed);
}

static int noisy_dgram_new(BIO *bio)
{
    BIO_set_init(bio, 1);

    return 1;
}

static int noisy_dgram_free(BIO *bio)
{
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
