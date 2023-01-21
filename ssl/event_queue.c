/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include "internal/event_queue.h"
#include "crypto/sparse_array.h"
#include "ssl_local.h"

struct ossl_event_queue_st {
    PRIORITY_QUEUE_OF(OSSL_EVENT) *timed_events;
    PRIORITY_QUEUE_OF(OSSL_EVENT) *now_events;
};

static int event_compare_times(const OSSL_EVENT *a, const OSSL_EVENT *b)
{
    return ossl_time_compare(a->when, b->when);
}

static int event_compare_priority(const OSSL_EVENT *a, const OSSL_EVENT *b)
{
    if (a->priority > b->priority)
        return -1;
    if (a->priority < b->priority)
        return 1;
    return 0;
}

OSSL_EVENT_QUEUE *ossl_event_queue_new(void)
{
    OSSL_EVENT_QUEUE *r = OPENSSL_malloc(sizeof(*r));

    if (r != NULL) {
        r->timed_events = ossl_pqueue_OSSL_EVENT_new(&event_compare_times);
        r->now_events = ossl_pqueue_OSSL_EVENT_new(&event_compare_priority);
        if (r->timed_events == NULL || r->now_events == NULL) {
            ossl_event_queue_free(r);
            return NULL;
        }
    }
    return r;
}

void ossl_event_free(OSSL_EVENT *event)
{
    if (event != NULL) {
        if (event->flag_dynamic)
            OPENSSL_free(event);
        else
            event->queue = NULL;
    }
}

static void event_queue_free(PRIORITY_QUEUE_OF(OSSL_EVENT) *queue)
{
    OSSL_EVENT *e;

    if (queue != NULL) {
        while ((e = ossl_pqueue_OSSL_EVENT_pop(queue)) != NULL)
            ossl_event_free(e);
        ossl_pqueue_OSSL_EVENT_free(queue);
    }
}

void ossl_event_queue_free(OSSL_EVENT_QUEUE *queue)
{
    if (queue != NULL) {
        event_queue_free(queue->now_events);
        event_queue_free(queue->timed_events);
        OPENSSL_free(queue);
    }
}

static ossl_inline
int event_queue_add(OSSL_EVENT_QUEUE *queue, OSSL_EVENT *event)
{
    PRIORITY_QUEUE_OF(OSSL_EVENT) *pq =
            ossl_time_compare(event->when, ossl_time_now()) <= 0
            ? queue->now_events
            : queue->timed_events;

    if (ossl_pqueue_OSSL_EVENT_push(pq, event, &event->ref)) {
        event->queue = pq;
        return 1;
    }
    return 0;
}

static ossl_inline
void ossl_event_set(OSSL_EVENT *event, uint32_t type, uint32_t priority,
                    OSSL_TIME when, void *ctx,
                    void *payload, size_t payload_size)
{
    event->type = type;
    event->priority = priority;
    event->when = when;
    event->ctx = ctx;
    event->payload = payload;
    event->payload_size = payload_size;
}

OSSL_EVENT *ossl_event_queue_add_new(OSSL_EVENT_QUEUE *queue, 
                                     uint32_t type, uint32_t priority,
                                     OSSL_TIME when, void *ctx,
                                     void *payload, size_t payload_size)
{
    OSSL_EVENT *e = OPENSSL_malloc(sizeof(*e));

    if (e == NULL || queue == NULL)
        return NULL;
    ossl_event_set(e, type, priority, when, ctx, payload, payload_size);
    e->flag_dynamic = 1;
    if (event_queue_add(queue, e))
        return e;
    OPENSSL_free(e);
    return NULL;
}

int ossl_event_queue_add(OSSL_EVENT_QUEUE *queue, OSSL_EVENT *event,
                         uint32_t type, uint32_t priority,
                         OSSL_TIME when, void *ctx,
                         void *payload, size_t payload_size)
{
    if (event == NULL || queue == NULL)
        return 0;
    ossl_event_set(event, type, priority, when, ctx, payload, payload_size);
    event->flag_dynamic = 0;
    return event_queue_add(queue, event);
}

int ossl_event_queue_remove(OSSL_EVENT_QUEUE *queue, OSSL_EVENT *event)
{
    if (event != NULL && event->queue != NULL) {
        ossl_pqueue_OSSL_EVENT_remove(event->queue, event->ref);
        event->queue = NULL;
    }
    return 1;
}

OSSL_TIME ossl_event_time_until(const OSSL_EVENT *event)
{
    if (event == NULL)
        return ossl_time_infinite();
    return ossl_time_subtract(event->when, ossl_time_now());
}

OSSL_TIME ossl_event_queue_time_until_next(const OSSL_EVENT_QUEUE *queue)
{
    if (queue == NULL)
        return ossl_time_infinite();
    if (ossl_pqueue_OSSL_EVENT_num(queue->now_events) > 0)
        return ossl_time_zero();
    return ossl_event_time_until(ossl_pqueue_OSSL_EVENT_peek(queue->timed_events));
}

int ossl_event_queue_postpone_until(OSSL_EVENT_QUEUE *queue,
                                    OSSL_EVENT *event,
                                    OSSL_TIME when)
{
    if (ossl_event_queue_remove(queue, event)) {
        event->when = when;
        return event_queue_add(queue, event);
    }
    return 0;
}

int ossl_event_queue_get1_next_event(OSSL_EVENT_QUEUE *queue,
                                     OSSL_EVENT **event)
{
    OSSL_TIME now = ossl_time_now();
    OSSL_EVENT *e;

    /* Check for expired timer based events and convert them to now events */
    while ((e = ossl_pqueue_OSSL_EVENT_peek(queue->timed_events)) != NULL
           && ossl_time_compare(e->when, now) <= 0) {
        e = ossl_pqueue_OSSL_EVENT_pop(queue->timed_events);
        if (!ossl_pqueue_OSSL_EVENT_push(queue->now_events, e, &e->ref)) {
            e->queue = NULL;
            return 0;
        }
    }

    /*
     * Get next event from the now queue.
     * The pop returns NULL when there is none.
     */
    *event = ossl_pqueue_OSSL_EVENT_pop(queue->now_events);
    return 1;
}
