/*
 * Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_EVENT_QUEUE_H
# define OSSL_INTERNAL_EVENT_QUEUE_H
# pragma once

# include "internal/priority_queue.h"
# include "internal/time.h"

/*
 * Opaque type holding an event.
 */
typedef struct ossl_event_st OSSL_EVENT;

DEFINE_PRIORITY_QUEUE_OF(OSSL_EVENT);

/*
 * Public type representing an event queue, the underlying structure being
 * opaque.
 */
typedef struct ossl_event_queue_st OSSL_EVENT_QUEUE;

/*
 * Public type representing a event queue entry.
 * It is (internally) public so that it can be embedded into other structures,
 * it should otherwise be treated as opaque.
 */
struct ossl_event_st {
    uint32_t type;              /* What type of event this is               */
    uint32_t priority;          /* What priority this event has             */
    OSSL_TIME when;             /* When the event is scheduled to happen    */
    void *ctx;                  /* User argument passed to call backs       */
    void *payload;              /* Event specific data of unknown kind      */
    size_t payload_size;        /* Length (in bytes) of event specific data */

    /* These fields are for internal use only */
    PRIORITY_QUEUE_OF(OSSL_EVENT) *queue;    /* Queue containing this event */
    size_t ref;                 /* ID for this event                        */
    unsigned int flag_dynamic : 1;  /* Malloced or not?                     */
};

/*
 * Utility function to populate an event structure and add it to the queue
 */
int ossl_event_queue_add(OSSL_EVENT_QUEUE *queue, OSSL_EVENT *event,
                         uint32_t type, uint32_t priority,
                         OSSL_TIME when, void *ctx,
                         void *payload, size_t payload_size);

/*
 * Utility functions to extract event fields
 */
static ossl_unused ossl_inline
uint32_t ossl_event_get_type(const OSSL_EVENT *event)
{
    return event->type;
}

static ossl_unused ossl_inline
uint32_t ossl_event_get_priority(const OSSL_EVENT *event)
{
    return event->priority;
}

static ossl_unused ossl_inline
OSSL_TIME ossl_event_get_when(const OSSL_EVENT *event)
{
    return event->when;
}

static ossl_unused ossl_inline
void *ossl_event_get0_ctx(const OSSL_EVENT *event)
{
    return event->ctx;
}

static ossl_unused ossl_inline
void *ossl_event_get0_payload(const OSSL_EVENT *event, size_t *length)
{
    if (length != NULL)
        *length = event->payload_size;
    return event->payload;
}

/*
 * Create and free a queue.
 */
OSSL_EVENT_QUEUE *ossl_event_queue_new(void);
void ossl_event_queue_free(OSSL_EVENT_QUEUE *queue);

/*
 * Schedule a new event into an event queue.
 *
 * The event parameters are taken from the function arguments.
 *
 * The function returns NULL on failure and the added event on success.
 */
OSSL_EVENT *ossl_event_queue_add_new(OSSL_EVENT_QUEUE *queue, 
                                     uint32_t type, uint32_t priority,
                                     OSSL_TIME when, void *ctx,
                                     void *payload, size_t payload_size)
;

/*
 * Schedule an event into an event queue.
 *
 * The event parameters are taken from the function arguments.
 *
 * The function returns 0 on failure and 1 on success.
 */
int ossl_event_queue_add(OSSL_EVENT_QUEUE *queue, OSSL_EVENT *event,
                         uint32_t type, uint32_t priority,
                         OSSL_TIME when, void *ctx,
                         void *payload, size_t payload_size);

/*
 * Delete an event from the queue.
 * This will cause the early deletion function to be called if it is non-NULL.
 * A pointer to the event structure is returned.
 */
int ossl_event_queue_remove(OSSL_EVENT_QUEUE *queue, OSSL_EVENT *event);

/*
 * Free a dynamic event.
 * Is a NOP for a static event.
 */
void ossl_event_free(OSSL_EVENT *event);

/*
 * Return the time until the next event for the specified event, if the event's
 * time is past, zero is returned.  Once activated, the event reference becomes
 * invalid and this function becomes undefined.
 */
OSSL_TIME ossl_event_time_until(const OSSL_EVENT *event);

/*
 * Return the time until the next event in the queue.
 * If the next event is in the past, zero is returned.
 */
OSSL_TIME ossl_event_queue_time_until_next(const OSSL_EVENT_QUEUE *queue);

/*
 * Postpone an event to trigger at the specified time.
 * If the event has triggered, this function's behaviour is undefined.
 */
int ossl_event_queue_postpone_until(OSSL_EVENT_QUEUE *queue,
                                    OSSL_EVENT *event,
                                    OSSL_TIME when);

/*
 * Return the next event to process.
 */
int ossl_event_queue_get1_next_event(OSSL_EVENT_QUEUE *queue,
                                     OSSL_EVENT **event);

#endif
