/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_EVENT_H
# define OSSL_INTERNAL_EVENT_H
# pragma once

# include <stddef.h>
# include <stdarg.h>
# include <openssl/safestack.h>
# include "crypto/sparse_array.h"

/*-
 * Types and structures
 * --------------------
 */

/*
 * An event is expected to be very short lived, and may be a static
 * (re-usable) variable, local in a function or other structure, or
 * dynamically allocated.
 */
struct ossl_event_st;
typedef int ossl_event_destructor_fn(struct ossl_event_st *event);

/*
 * Generic callback function type.  This is used for subscribers and filters
 * alike, as seen in the different functions where this type is used.
 */
typedef int ossl_event_callback_fn(struct ossl_event_st *event,
                                   void *callback_data);

struct ossl_event_st {
    /*
     * Mandatory data.
     *
     * These fields are considered immutable.  However, the contents that
     * |ctx| points at may be mutable.
     */

    /*
     * A numeric event identity, defined by the using functionality
     * These identities must remain within the range 0-63, as bits in a
     * 64-bit bitfield are used to match multiple event types at once.
     */
    uint32_t type;
    /* A context relevant for the using functionality */
    void *ctx;

    /*
     * Optional data (may be NULL or zero).
     *
     * These fields are considered mutable, in so far that an event handler
     * may "steal" them, and replace them with NULL.
     *
     * The Identifying material and the payload are kept separate, because
     * it's not certain that they come from the same source, or are located
     * consecutively in memory.
     */

    /*
     * Time value.
     *
     * When non-zero, this denotes earliest time that this event should be
     * fired off (passed to subscribers).
     */
    OSSL_TIME when;

    /* Identifying material */
    const void *identifiers;
    /* Data carried by the event */
    size_t payload_size;
    void *payload;

    /*
     * A destructor for |identifiers| and |payload|, if necessary.
     *
     * This field is considered immutable until the event is destroyed.
     */
    ossl_event_destructor_fn *destructor;

    /*
     * Flags, only relevant for the event functionality itself.
     */
    unsigned int flag_dynamic : 1;
};

/*
 * The event queue is expected to be very long lived, even thought it may be
 * dynamically allocated.  Subsribers are expected to return values that
 * express if the event it received was used or not.
 */
enum ossl_event_subscriber_returns {
    /* The subscriber encountered an error */
    ossl_event_error = -1,
    /* The subscriber didn't use this event */
    ossl_event_pass = 0,
    /* The subscriber used this event */
    ossl_event_handled = 1,
};

/*
 * OSSL_EVENT_SUBSCRIBER_CLOSURE implements a closure simile, speciflcally
 * for our event callbacks, to carry along the callback specific data pointer.
 */
typedef struct ossl_event_subscriber_closure_st {
    uint64_t event_types;
    ossl_event_callback_fn *cb;
    void *cbarg;
} OSSL_EVENT_SUBSCRIBER_CLOSURE;

/*
 * Opaque definition, to allow an optimal internal implementation without
 * having to change anything else.
 * This structure is expected to have the semantics of an array of stacks
 * of events, and should only be affected by event addition, event removal
 * and event dispatching, all of is internal code in crypto/event/event.c.
 *
 * Each element in this implied array represent a priority level, and each
 * stack (element in this array) simply stores the events for its priority
 * level in a FIFO manner; events get pushed in and shifted out.
 */
struct ossl_events_stacks_st;

struct ossl_event_queue_method_st;
struct ossl_event_queue_st {
    const struct ossl_event_queue_method_st *method;
    void *method_data;

    /*
     * The number of subscribers determine how many subscribers are listening
     * to events passing through this queue.  The number of subscribers may
     * change dynamically.
     */
    STACK_OF(OSSL_EVENT_SUBSCRIBER_CLOSURE) *subscribers;

    /*
     * Buckets of events
     *
     * The |ossl_events_buckets_st| is semantically an array of event queues,
     * on queue for each priority level this |ossl_event_queue_st| will be
     * used for.
     * The exact implementation isn't specified here.  It might be done as
     * an array of doubly linked lists, but it might as well be a single
     * array sorted by priority level and event insertion timestamp.
     *
     * It's possible to have no buckets at all, i.e. for this field to be
     * NULL.  In that case, the event publishing function will dispatch
     * events to the subscribers immediately.
     */
    struct ossl_events_buckets_st *events_buckets;

    /*
     * Flags, only relevant for the event functionality itself.
     */
    unsigned int flag_dynamic : 1;
};

/*
 * The event queue method is expected to be static, even if allocated
 * dynamically.
 */
struct ossl_event_queue_method_st {
    /*
     * Initialize the auxilliary data
     *
     * Expected to return 1 on success, -1 on failure.
     */
    int (*init_data)(struct ossl_event_queue_st *queue);

    /*
     * Destroy the auxilliary data
     *
     * Expected to return 1 on success, -1 on failure.
     */
    int (*destroy_data)(struct ossl_event_queue_st *queue);

    /*
     * For a multi-priority queue implementation, this function helps
     * determine in which event stack the event should end up in.
     *
     * Expected to return the priority (which may be zero), or -1 on error
     */
    int (*determine_priority)(struct ossl_event_st *event);

    /*
     * Whenever events have been dispatched to the subscribers, the diverse
     * return values are counted, and this function is used to determined
     * how to act on that result.  The returned value is simply returned
     * back to whoever is calling.
     *
     * |count_errors| is the count of any subscriber call that returned
     * |ossl_event_error|.
     * |count_success| is the count of any subscriber call that returned
     * |ossl_event_pass| or |ossl_event_handled|.
     *
     * Expected to return 1 for good (may continue to be used), -1 for bad
     * (this queue is not functional any more).
     */
    int (*determine_state)(size_t count_errors, size_t count_success);

    /*
     * Set / get values to / from auxilliary queue method data, or perform
     * other queue method specific tasks.
     *
     * The functionality this implements is open ended, and allows
     * extraordinary operations such as reordering (rescheduling) events,
     * affecting other associated queues, as well as modifications or access
     * of the auxialliary method data, etc etc etc.
     * Use with care!
     *
     * The arguments are of the same style as ioctl.h functions.  The caller
     * must know exactly what arguments are expected for each |request|.
     *
     * Expected to return 1 on success, -1 on failure.
     */
    int (*ctrl)(struct ossl_event_queue_st *queue, uint32_t request,
                ... /* args */);
    /* va_list variant of the control function */
    int (*vctrl)(struct ossl_event_queue_st *queue, uint32_t request,
                 va_list args);

/*
 * Request the nummber of priorities for this method.
 * Takes on extra argument:
 * - a pointer to size_t, where the number of priorities will be stored
 *
 * This is a special request; it expects NULL for |queue|, and gives back a
 * constant number.
 */
# define OSSL_EVENT_C_PRIORITIES    0x00000001
};

/*-
 * Functions to create and populate events
 * ---------------------------------------
 */

/* Allocate / deallocate an event structure dynamically and populate it */
struct ossl_event_st *ossl_event_new(uint32_t type, void *ctx, OSSL_TIME when,
                                     const void *identifiers,
                                     void *payload, size_t payload_size,
                                     ossl_event_destructor_fn *destructor);
void ossl_event_free(struct ossl_event_st *);

/*
 * Populate an event structure.  Used for events that aren't allocated
 * dynamically.
 *
 * Returns one of these values:
 * 0    Not set
 * 1    Set
 */
int ossl_event_set0(struct ossl_event_st *event,
                    uint32_t type, void *ctx, OSSL_TIME when,
                    const void *identifiers,
                    void *payload, size_t payload_size,
                    ossl_event_destructor_fn *destructor);

/*
 * Functions to create and populate event queues
 * ---------------------------------------------
 */

/* Allocate / deallocate an event queue dynamically */
struct ossl_event_queue_st *
ossl_event_queue_new(const struct ossl_event_queue_method_st *method);
void ossl_event_queue_free(struct ossl_event_queue_st *queue);

/*
 * Populate an event queue structure.  Used for event queues that aren't
 * allocated dynamically.
 *
 * Returns one of these values:
 * 0    Not set
 * 1    Set
 */
int ossl_event_queue_set0(struct ossl_event_queue_st *queue,
                          const struct ossl_event_queue_method_st *method);

/*
 * Subscribe / unsubscribe to events on an event queue
 *
 * Returns one of these values:
 * -1   Error
 *  0   Not found (unsubscibe only)
 *  1   Subscribed / unsubscribed
 */
int ossl_event_queue_subscribe(struct ossl_event_queue_st *queue,
                               uint64_t event_types,
                               ossl_event_callback_fn *subscriber,
                               void *subscriber_data);

int ossl_event_queue_unsubscribe(struct ossl_event_queue_st *queue,
                                 ossl_event_callback_fn *subscriber,
                                 void *subscriber_data);

/*-
 * Functions to publish and to wait for events
 * -------------------------------------------
 */

/*
 * Add an event to the queue
 *
 * Returns one of these values:
 *
 * -1   Error
 *  0   Event not added (because there's no actual queue)
 *  1   Event added
 *
 * If 0 is returned, an option is to use ossl_event_queue_add_and_wait_for().
 */
int ossl_event_queue_add(struct ossl_event_queue_st *queue,
                         struct ossl_event_st *event);

/*
 * Remove events from the queue, based on the result of calling the filter
 *
 * Returns one of these values:
 *
 * -1   Error
 *  0   There were no events to remove, according to the |filter| call
 *  1   Events were removed
 */
int ossl_event_queue_remove(struct ossl_event_queue_st *queue,
                            ossl_event_callback_fn *filter,
                            void *filter_data);

/*
 * Wait for an event
 *
 * This will dispatch all queued events until |subscriber| has been run and
 * returned something other than |ossl_event_pass|, or until there are no
 * more events queued in |queue|.
 *
 * Returns one of these values:
 *
 * -1   Error
 *  0   |subscriber| was never run, or always returned |ossl_event_pass|
 *  1   |subscriber| was run, and returned something other than |ossl_event_pass|
 */
int ossl_event_queue_wait_for(struct ossl_event_queue_st *queue,
                              uint64_t event_types,
                              ossl_event_callback_fn *subscriber,
                              void *subscriber_data);

/*
 * Add or dispatch an event and wait for another.
 *
 * This is used for bi-directional event pipes.  For example, it could be
 * used to send a read-request event and wait for a resulting read event.
 *
 * This will add |event| to the queue and then dispatch all queued events
 * until |subscriber| has been run and returned something other than
 * |ossl_event_pass|, or until there are no more events queued in |queue|.
 *
 * This may also dispatch |event| immediately, if |queue| doesn't have any
 * |events_stacks|.
 *
 * Returns one of these values:
 *
 * -1   Error
 *  0   |subscriber| was never run, or returned |ossl_event_pass|
 *  1   |subscriber| was run, and returned something other than |ossl_event_pass|
 */
int ossl_event_queue_add_and_wait_for(struct ossl_event_st *event,
                                      struct ossl_event_queue_st *queue,
                                      uint64_t event_types,
                                      ossl_event_callback_fn *subscriber,
                                      void *subscriber_data);

/*-
 * Functions to dispatch queued events
 * -----------------------------------
 *
 * It's encouraged to use ossl_event_queue_wait_for() or
 * ossl_event_queue_add_and_wait_for() rather than these functions,
 * but there may be times, when it's preferred to add events and dispatch
 * events separately.
 */

/*
 * Dispatch one event from the given queue
 *
 * Returns one of the following values:
 *
 * -1    Error
 *  0    No events in the queue (that is not an error)
 *  1    One event dispatched
 */
int ossl_event_queue_dispatch(struct ossl_event_queue_st *queue);

#endif
