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

#define MSG_DATA_LEN_MAX    1472

struct noisy_dgram_st {
    uint64_t this_dgram;
    BIO_MSG msg;
    uint64_t delayed_dgram;
};

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

static void get_noise(uint64_t *delay, int *should_drop)
{
    uint32_t type;

    /* 20% of all datagrams should be noisy */
    if (test_random() % 5 != 0) {
        *delay = 0;
        *should_drop = 0;
        return;
    }

    type = test_random() % 3;

    /* Of noisy datagrams, 33% drop only, 33% delay only, 33% drop and delay */

    *should_drop = (type == 0 || type == 1);

    /* Where a delay occurs we delay by 1 - 4 datagrams */
    *delay = (type == 0) ? 0 : (uint64_t)((test_random() % 4) + 1);

    /*
     * No point in delaying by 1 datagram if we are also dropping, so we delay
     * by an extra datagram in that case
     */
    *delay += (uint64_t)(*should_drop);
}

static int noisy_dgram_recvmmsg(BIO *bio, BIO_MSG *msg, size_t stride,
                                size_t num_msg, uint64_t flags,
                                size_t *msgs_processed)
{
    BIO *next = BIO_next(bio);
    size_t i, j, data_len = 0, msg_cnt = 0;
    BIO_MSG *thismsg;
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
        if (i == 0) {
            data_len = msg[i].data_len;
            if (!TEST_size_t_le(data_len, MSG_DATA_LEN_MAX))
                return 0;
        } else if (!TEST_size_t_eq(msg[i].data_len, data_len)) {
            return 0;
        }
    }

    if (!BIO_recvmmsg(next, msg, stride, num_msg, flags, msgs_processed))
        return 0;

#ifdef OSSL_NOISY_DGRAM_DEBUG
    printf("Pre-filter datagram list:\n");
    for (i = 0; i < *msgs_processed; i++) {
        printf("Pre-filter Datagram:\n");
        BIO_dump_fp(stdout, msg[i].data, msg[i].data_len);
        printf("\n");
    }
    printf("End of pre-filter datagram list\nApplying noise filters:\n");
#endif

    msg_cnt = *msgs_processed;

    /* Introduce noise */
    for (i = 0, thismsg = msg;
         i < msg_cnt;
         i++, thismsg++, data->this_dgram++) {
        uint64_t delay;
        int should_drop;

        /* If we have a delayed message ready insert it now */
        if (data->delayed_dgram > 0
                && data->delayed_dgram == data->this_dgram) {
            if (msg_cnt < num_msg) {
                /* Make space for the inserted message */
                for (j = msg_cnt; j > i; j--) {
                    if (!bio_msg_copy(&msg[j], &msg[j - 1]))
                        return 0;
                }
                if (!bio_msg_copy(thismsg, &data->msg))
                    return 0;
                msg_cnt++;
                data->delayed_dgram = 0;
#ifdef OSSL_NOISY_DGRAM_DEBUG
                printf("**Inserting a delayed datagram\n");
                BIO_dump_fp(stdout, thismsg->data, thismsg->data_len);
                printf("\n");
#endif
                continue;
            } /* else we have no space for the insertion, so just drop it */
            data->delayed_dgram = 0;
        }

        get_noise(&delay, &should_drop);

        /* We ignore delay if a message is already delayed */
        if (delay > 0 && data->delayed_dgram == 0) {
            /*
             * Note that a message may be delayed *and* dropped, or delayed
             * and *not* dropped.
             * Delayed and dropped means the message will not be sent now and
             * will only be sent after the delay.
             * Delayed and not dropped means the message will be sent now and
             * a duplicate will also be sent after the delay.
             */

            if (!bio_msg_copy(&data->msg, thismsg))
                return 0;

            data->delayed_dgram = data->this_dgram + delay;

#ifdef OSSL_NOISY_DGRAM_DEBUG
            printf("**Delaying a datagram for %u messages%s\n",
                   (unsigned int)delay, should_drop ? "" : "(duplicating)");
            BIO_dump_fp(stdout, thismsg->data, thismsg->data_len);
            printf("\n");
#endif
        }

        if (should_drop) {
#ifdef OSSL_NOISY_DGRAM_DEBUG
            printf("**Dropping a datagram\n");
            BIO_dump_fp(stdout, thismsg->data, thismsg->data_len);
            printf("\n");
#endif
            for (j = i + 1; j < msg_cnt; j++) {
                if (!bio_msg_copy(&msg[j - 1], &msg[j]))
                    return 0;
            }
            msg_cnt--;
        }
    }

#ifdef OSSL_NOISY_DGRAM_DEBUG
    printf("End of noise filters\nPost-filter datagram list:\n");
    for (i = 0; i < msg_cnt; i++) {
        printf("Post-filter Datagram:\n");
        BIO_dump_fp(stdout, msg[i].data, msg[i].data_len);
        printf("\n");
    }
    printf("End of post-filter datagram list\n");
#endif

    *msgs_processed = msg_cnt;

    if (msg_cnt == 0) {
        ERR_raise(ERR_LIB_BIO, BIO_R_NON_FATAL);
        return 0;
    }

    return 1;
}

static void data_free(struct noisy_dgram_st *data)
{
    if (data == NULL)
        return;

    OPENSSL_free(data->msg.data);
    BIO_ADDR_free(data->msg.peer);
    BIO_ADDR_free(data->msg.local);
    OPENSSL_free(data);
}

static int noisy_dgram_new(BIO *bio)
{
    struct noisy_dgram_st *data = OPENSSL_zalloc(sizeof(*data));

    if (!TEST_ptr(data))
        return 0;

    data->msg.data = OPENSSL_malloc(MSG_DATA_LEN_MAX);
    data->msg.peer = BIO_ADDR_new();
    data->msg.local = BIO_ADDR_new();
    if (data->msg.data == NULL
            || data->msg.peer == NULL
            || data->msg.local == NULL) {
        data_free(data);
        return 0;
    }

    BIO_set_data(bio, data);
    BIO_set_init(bio, 1);

    return 1;
}

static int noisy_dgram_free(BIO *bio)
{
    data_free(BIO_get_data(bio));
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
