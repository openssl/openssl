/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/event_queue.h"
#include "internal/nelem.h"
#include "testutil.h"

static OSSL_TIME cur_time = { 100 };

OSSL_TIME ossl_time_now(void)
{
    return cur_time;
}

#define PAYLOAD(s)  s, strlen(s) + 1

static int event_test(void)
{
    int res = 0;
    size_t len = 0;
    OSSL_EVENT *e1, *e2, e3, *e4 = NULL, *ep = NULL;
    OSSL_EVENT_QUEUE *q = NULL;
    void *p;
    static char payload[] = "payload";

    /* Create an event queue and add some events */
    if (!TEST_ptr(q = ossl_event_queue_new())
            || !TEST_ptr(e1 = ossl_event_queue_add_new(q, 1, 10,
                                                       ossl_ticks2time(1100),
                                                       "ctx 1",
                                                       PAYLOAD(payload)))
            || !TEST_ptr(e2 = ossl_event_queue_add_new(q, 2, 5,
                                                       ossl_ticks2time(1100),
                                                       "ctx 2",
                                                       PAYLOAD("data")))
            || !TEST_true(ossl_event_queue_add(q, &e3, 3, 20,
                                               ossl_ticks2time(1200), "ctx 3",
                                               PAYLOAD("more data")))
            || !TEST_ptr(e4 = ossl_event_queue_add_new(q, 2, 5,
                                                       ossl_ticks2time(1150),
                                                       "ctx 2",
                                                       PAYLOAD("data")))

            /* Verify some event details */
            || !TEST_uint_eq(ossl_event_get_type(e1), 1)
            || !TEST_uint_eq(ossl_event_get_priority(e1), 10)
            || !TEST_uint64_t_eq(ossl_time2ticks(ossl_event_get_when(e1))
                                 , 1100)
            || !TEST_str_eq(ossl_event_get0_ctx(e1), "ctx 1")
            || !TEST_ptr(p = ossl_event_get0_payload(e1, &len))
            || !TEST_str_eq((char *)p, payload)
            || !TEST_uint64_t_eq(ossl_time2ticks(ossl_event_time_until(&e3)),
                                 1100)
            || !TEST_uint64_t_eq(ossl_time2ticks(ossl_event_queue_time_until_next(q)),
                                 1000)

            /* Modify an event's time */
            || !TEST_true(ossl_event_queue_postpone_until(q, e1,
                                                          ossl_ticks2time(1200)))
            || !TEST_uint64_t_eq(ossl_time2ticks(ossl_event_get_when(e1)), 1200)
            || !TEST_true(ossl_event_queue_remove(q, e4)))
        goto err;
    ossl_event_free(e4);

    /* Execute the queue */
    cur_time = ossl_ticks2time(1000);
    if (!TEST_true(ossl_event_queue_get1_next_event(q, &ep))
            || !TEST_ptr_null(ep))
        goto err;
    cur_time = ossl_ticks2time(1100);
    if (!TEST_true(ossl_event_queue_get1_next_event(q, &ep))
            || !TEST_ptr_eq(ep, e2))
        goto err;
    ossl_event_free(ep);
    ep = e2 = NULL;
    if (!TEST_true(ossl_event_queue_get1_next_event(q, &ep))
            || !TEST_ptr_null(ep))
        goto err;

    cur_time = ossl_ticks2time(1250);
    if (!TEST_true(ossl_event_queue_get1_next_event(q, &ep))
            || !TEST_ptr_eq(ep, &e3))
        goto err;
    ossl_event_free(ep);
    ep = NULL;
    if (!TEST_true(ossl_event_queue_get1_next_event(q, &ep))
            || !TEST_ptr_eq(ep, e1))
        goto err;
    ossl_event_free(ep);
    ep = e1 = NULL;
    if (!TEST_true(ossl_event_queue_get1_next_event(q, &ep))
            || !TEST_ptr_null(ep))
        goto err;

    res = 1;
 err:
    ossl_event_free(ep);
    ossl_event_queue_free(q);
    return res;
}

int setup_tests(void)
{
    ADD_TEST(event_test);
    return 1;
}
