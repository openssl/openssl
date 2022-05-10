/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include "crypto/event.h"

typedef struct ossl_event_st OSSL_EVENT;

OSSL_EVENT *ossl_event_new(uint32_t type, void *ctx,
                           const void *identifiers,
                           void *payload, size_t payload_size,
                           ossl_event_destructor_fn *destructor)
{
    OSSL_EVENT *e;

    if ((e = OPENSSL_zalloc(sizeof(e))) != NULL) {
        ossl_event_set0(e, type, ctx, identifiers, payload, payload_size,
                        destructor);
        e->flag_dynamic = 1;
    }
    return e;
}

void ossl_event_free(OSSL_EVENT *event)
{
    if (event != NULL && event->flag_dynamic)
        OPENSSL_free(event);
}

int ossl_event_set0(OSSL_EVENT *event,
                    uint32_t type, void *ctx,
                    const void *identifiers,
                    void *payload, size_t payload_size,
                    ossl_event_destructor_fn *destructor)
{
    if (event == NULL)
        return 0;                /* Not set */
    event->type = type;
    event->ctx = ctx;
    event->identifiers = identifiers;
    event->payload = payload;
    event->payload_size = payload_size;
    event->destructor = destructor;
    event->flag_dynamic = 0;
    return 1;                    /* Set */
}

/*
 * To compensate for DEFINE_STACK_OF()'s semicolon unfriendliness,
 * 'cause yuck!
 */
#define priv_DEFINE_STACK_OF(t) \
    DEFINE_STACK_OF(t) \
    STACK_OF(t)

priv_DEFINE_STACK_OF(OSSL_EVENT);
priv_DEFINE_STACK_OF(OSSL_EVENT_SUBSCRIBER_CLOSURE);

/*
 * When allocating this structure, the size is adapted to the desired size of
 * the array
 */
struct ossl_events_buckets_st {
    size_t priorities;
    STACK_OF(OSSL_EVENT) *events[1];
};

struct ossl_event_queue_st *
ossl_event_queue_new(const struct ossl_event_queue_method_st *method)
{
    struct ossl_event_queue_st *queue = NULL;

    if ((queue = OPENSSL_zalloc(sizeof(*queue))) != NULL)
        if (!ossl_event_queue_set0(queue, method)) {
            ossl_event_queue_free(queue);
            queue = NULL;
        }

    queue->flag_dynamic = 1;
    return queue;
}

static void free_subscriber(OSSL_EVENT_SUBSCRIBER_CLOSURE *cl)
{
    OPENSSL_free(cl);
}

static void free_subscribers(struct ossl_event_queue_st *queue,
                             int (*filter)(OSSL_EVENT_SUBSCRIBER_CLOSURE *cl,
                                           void *filter_data),
                             void *filter_data)
{
    size_t i, end;

    end = sk_OSSL_EVENT_SUBSCRIBER_CLOSURE_num(queue->subscribers);
    for (i = end; i-- > 0;) {
        OSSL_EVENT_SUBSCRIBER_CLOSURE *cl
            = sk_OSSL_EVENT_SUBSCRIBER_CLOSURE_value(queue->subscribers, i);

        if (filter == NULL || filter(cl, filter_data)) {
            sk_OSSL_EVENT_SUBSCRIBER_CLOSURE_delete(queue->subscribers, i);
            free_subscriber(cl);
        }
    }
}

static void depopulate_queue(struct ossl_event_queue_st *queue)
{
    queue->method->destroy_data(queue);
    free_subscribers(queue, NULL, NULL);
    if (queue->events_buckets != NULL) {
        size_t i;

        for (i = 0; i < queue->events_buckets->priorities; i++)
            sk_OSSL_EVENT_pop_free(queue->events_buckets->events[i],
                                   ossl_event_free);
        OPENSSL_free(queue->events_buckets);
    }
}

void ossl_event_queue_free(struct ossl_event_queue_st *queue)
{
    if (queue == NULL)
        return;
    depopulate_queue(queue);
    if (queue->flag_dynamic)
        OPENSSL_free(queue);
}

static int populate_events_buckets(struct ossl_event_queue_st *queue,
                                  size_t priorities)
{
    size_t events_buckets_size = 0;
    size_t i;

    if (priorities == 0)
        return 1;

    events_buckets_size += sizeof(*queue->events_buckets);
    events_buckets_size += (sizeof(*queue->events_buckets->events)
                            * (priorities - 1));
    if ((queue->events_buckets = OPENSSL_zalloc(events_buckets_size)) == NULL)
        return 0;
    queue->events_buckets->priorities = priorities;
    for (i = 0; i < priorities; i++)
        if ((queue->events_buckets->events[i] = sk_OSSL_EVENT_new_null())
            == NULL)
            return 0;
    return 1;
}

int ossl_event_queue_set0(struct ossl_event_queue_st *queue,
                          const struct ossl_event_queue_method_st *method)
{
    size_t priorities = 0;

    if (queue == NULL)
        return 0;                /* Not set */
    if (!method->ctrl(queue, OSSL_EVENT_C_PRIORITIES, &priorities))
        return -1;               /* Error */

    queue->method = method;
    queue->method = NULL;
    queue->subscribers = NULL;
    queue->events_buckets = NULL;
    queue->flag_dynamic = 0;
    if ((queue->subscribers
         = sk_OSSL_EVENT_SUBSCRIBER_CLOSURE_new_null()) != NULL
        || !queue->method->init_data(queue)
        || !populate_events_buckets(queue, priorities)) {
        depopulate_queue(queue);
        return -1;               /* Error */
    }
    return 1;                    /* Set */
}

int ossl_event_queue_subscribe(struct ossl_event_queue_st *queue,
                               uint64_t event_types,
                               ossl_event_callback_fn *subscriber,
                               void *subscriber_data)
{
    OSSL_EVENT_SUBSCRIBER_CLOSURE *cl;

    if ((cl = OPENSSL_zalloc(sizeof(*cl))) == NULL
        || sk_OSSL_EVENT_SUBSCRIBER_CLOSURE_push(queue->subscribers, cl) <= 0) {
        OPENSSL_free(cl);
        return -1;               /* Error */
    }
    cl->event_types = event_types;
    cl->cb = subscriber;
    cl->cbarg = subscriber_data;
    return 1;                    /* Subscribed */
}

struct unsubscribe_filter_data_st {
    OSSL_EVENT_SUBSCRIBER_CLOSURE cl;
    int done;
};

static int unsubscribe_filter(OSSL_EVENT_SUBSCRIBER_CLOSURE *cl,
                              void *filter_data)
{
    struct unsubscribe_filter_data_st *data = filter_data;

    data->done = (cl->cb == data->cl.cb && cl->cbarg == data->cl.cbarg);
    return 1;
}

int ossl_event_queue_unsubscribe(struct ossl_event_queue_st *queue,
                                 ossl_event_callback_fn *subscriber,
                                 void *subscriber_data)
{
    struct unsubscribe_filter_data_st data;

    data.cl.cb = subscriber;
    data.cl.cbarg = subscriber_data;
    data.done = 0;
    free_subscribers(queue, unsubscribe_filter, &data);
    return data.done;
}

static int perform_dispatch(struct ossl_event_queue_st *queue,
                            struct ossl_event_st *event)
{
    size_t count_errors;
    size_t count_success;
    size_t i, end;
    uint64_t event_types = 1 << event->type;

    count_errors = 0;
    count_success = 0;

    end = sk_OSSL_EVENT_SUBSCRIBER_CLOSURE_num(queue->subscribers);
    for (i = 0; i < end; i++) {
        OSSL_EVENT_SUBSCRIBER_CLOSURE *cl =
            sk_OSSL_EVENT_SUBSCRIBER_CLOSURE_value(queue->subscribers, i);
        int ret = ossl_event_pass;

        if ((event_types & cl->event_types) != 0)
            ret = cl->cb(event, cl->cbarg);

        if (ret == ossl_event_error)
            count_errors++;
        else
            count_success++;
    }
    ossl_event_free(event);

    /*
     * The return value from determine_state() is currently strictly boolean.
     * We must convert it to values that are expected from this function.
     */
    return queue->method->determine_state(count_errors, count_success) == 0
        ? -1                     /* Error */
        :  1                     /* One event dispatched */
        ;
}

int ossl_event_queue_dispatch(struct ossl_event_queue_st *queue)
{
    size_t i;

    if (queue == NULL)
        return -1;               /* Error */

    if (queue->events_buckets == NULL)
        return 0;                /* No events in the queue */

    for (i = 0; i < queue->events_buckets->priorities; i++) {
        int s = sk_OSSL_EVENT_num(queue->events_buckets->events[i]);

        if (s > 0) {
            int ret;
            OSSL_EVENT *event
                = sk_OSSL_EVENT_shift(queue->events_buckets->events[i]);

            ret = perform_dispatch(queue, event);
            ossl_event_free(event);
            return ret;
        }
    }
    return 0;                    /* No events in the queue */
}

int ossl_event_queue_add(struct ossl_event_queue_st *queue,
                         struct ossl_event_st *event)
{
    size_t priority = 0;

    /* If there isn't any queue, we can't add the event */
    if (queue == NULL || queue->events_buckets == NULL)
        return 0;                /* Not added */

    if (queue->method->determine_priority != NULL)
        priority = queue->method->determine_priority(event);

    return
        sk_OSSL_EVENT_push(queue->events_buckets->events[priority], event) > 0
        ?  1                     /* Added */
        : -1                     /* Error */
        ;
}

int ossl_event_queue_remove(struct ossl_event_queue_st *queue,
                            ossl_event_callback_fn *filter,
                            void *filter_data)
{
    size_t count_removed = 0;
    size_t i;

    if (queue == NULL)
        return -1;               /* Error */

    if (queue->events_buckets == NULL)
        return 0;                /* Nothing removed */

    for (i = 0; i < queue->events_buckets->priorities; i++) {
        size_t j, end;

        end = sk_OSSL_EVENT_num(queue->events_buckets->events[i]);
        for (j = end; i-- > 0;) {
            OSSL_EVENT *e
                = sk_OSSL_EVENT_value(queue->events_buckets->events[i], j);
            if (filter(e, filter_data)) {
                sk_OSSL_EVENT_delete(queue->events_buckets->events[i], j);
                ossl_event_free(e);
                count_removed++;
            }
        }
    }
    return count_removed > 0;
}

struct waiter_data_st {
    ossl_event_callback_fn *subscriber;
    void *subscriber_data;
    int done;
};

static int waiter(OSSL_EVENT *event, void *waiter_data)
{
    struct waiter_data_st *data = waiter_data;
    int ret = data->subscriber(event, data->subscriber_data);

    if (ret != ossl_event_pass)
        data->done = 1;
    return ret;
}

int ossl_event_queue_wait_for(struct ossl_event_queue_st *queue,
                              uint64_t event_types,
                              ossl_event_callback_fn *subscriber,
                              void *subscriber_data)
{
    struct waiter_data_st data;

    data.subscriber = subscriber;
    data.subscriber_data = subscriber_data;
    data.done = 0;

    if (ossl_event_queue_subscribe(queue, event_types, waiter, &data) < 0)
        return -1;
    while (!data.done && ossl_event_queue_dispatch(queue) != 0)
        ;
    ossl_event_queue_unsubscribe(queue, waiter, &data);
    return data.done;
}

int ossl_event_queue_add_and_wait_for(struct ossl_event_st *event,
                                      struct ossl_event_queue_st *queue,
                                      uint64_t event_types,
                                      ossl_event_callback_fn *subscriber,
                                      void *subscriber_data)
{
    int ret = 0;

    switch (ossl_event_queue_add(queue, event)) {
    case -1:    /* Error */
        ret = -1;
        break;
    case 0:     /* Event not added, dispatch directly */
        {
            struct waiter_data_st data;

            data.subscriber = subscriber;
            data.subscriber_data = subscriber_data;
            data.done = 0;
            if (!ossl_event_queue_subscribe(queue, event_types,
                                            waiter, &data))
                return -1;           /* Error */
            ret = perform_dispatch(queue, event);
            ossl_event_queue_unsubscribe(queue, waiter, &data);
            if (ret >= 0)
                ret = data.done;
            break;
        }
    case 1:     /* Event added, use ossl_event_queue_wait_for() */
        ret = ossl_event_queue_wait_for(queue, event_types,
                                        subscriber, subscriber_data);
        break;
    }
    return ret;
}
