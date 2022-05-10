Event Queue and Event Dispatching design
========================================

Background
----------

For future I/O, especially to implement QUIC, a need for a generic event
queue and event dispatcher has been identified.

General description
-------------------

The general abstract model is to view an event queue as the connecting bit
between two parts of a pipe through which an event is passed.

Events themselves are carriers of information.

The event queue and event dispatching designed here is currently entirely
internal.  Public facing functionality is expected to "translate" events
into something that makes sense for the public functionality.

A publisher / subscriber model is supported primarly.  Events are considered
activate when added to the queue, even though dispatching them to subscribers
may be delayed, depending on when that dispatch actually happens.

For timers, it means that timer events are expected to be added to the queue
at the time the timer is supposed to trip.  To make timer events timely,
they should be considered very high priority.

For all event related structures and functions, `ossl_event_` is the naming
prefix.  If this becomes a public API, the prefix will be upcased as usual,
i.e. become `OSSL_EVENT_`.

### Event

An event is a small short-lived structure carrying information:

-   *[mandatory]* An event type, which is a simple numeric identity, the
    meaning of which is not known by the event functionality itself.
-   *[mandatory]* A reference to an event context
-   *[optional]* A reference to auxilliary identifying information.
-   *[optional]* A reference to a payload, which is data passed with the
    event (for example, a read event would carry along a buffer with data)
-   *[optional]* A reference to a desctructor function, if there are fields
    that need customized destruction when the event structure itself is to
    be destroyed.

The event itself is designed for a single synchronous thread, i.e. cannot be
shared by multiple threads.  The diverse objects it refers to may, however,
be shared by multiple threads, at the discretion of the functions in the
method structure.

Once populated, the event type, the references to event context, and the
reference to the destructor function are considered immutable, up until the
event structure is destroyed.

The reference to the auxilliary identifying material or to the payload,
however, are considered mutable.  Any event handler may "steal" them and
replace the reference to them in the event structure with NULL.  Stealing
must be done with much care.

Events may be dynamically allocated.  In that case, ownership is passed to
the event dispatch functionality (see below), and the event will be
automatically destroyed when not needed any more.

Events may also be embedded in another structure, as a static variable, or
as an local variable in a function.  In that case, owndership remains with
that structure or that variable.

### Event queue

An event queue is a structure holding the following:

-   A reference to a method structure to handle the event queue.
-   A reference to auxilliary data for the methods.
-   An array of subscribers, which are simple callbacks taking a reference
    to an event structure, along with auxilliary arguments.
-   Stacks of events.  The number of such arrays depends on how many
    priority levels are implemented by the functions of the method
    structure.
    If there are zero priority levels, there is no array of events at all,
    and events "added" to such a queue structure are always dispatched
    immediately, if the function used to "add" the event supports that.

#### Associated structures and services

The ctrl() function in the method structure of an event queue may manipulate
the auxilliary data, as well as perform extraordinary actions that affect
other structures, such as other event queues, as well as the event queue
that such calls originate from.

Similarly, subscribers may affect other structures, even other event queues,
assuming that references to them are passed as part of the subscriber data.

This can be useful for "services" such as a loss detector, congestion control,
etc.

A very concrete example:

Let's assume that packet retransmit data is stored in a structure somewhere
(lets call it a retransmission queue), to be retrasmitted at some point.

Two things can happen:

1.  An ACK is received, triggering a READ event with ACK payload.
2.  A timer event for retransmission is triggered.

The action to perform for each case is:

1.  The event subscriber finds the retransmit data corresponding to the ACK
    data and removes it from the the retransmission queue.
2.  The timer event subscriber retransmits packets according to every items
    it finds in the retransmission queue.

This is essentially a race between the two cases, may the first one win.

API
---

The API is defined by [`include/crypto/event.h`](../../include/crypto/event.h).

Usage examples
--------------

``` C
/*
 * An internal socket reader, passing the data back by sending an event with
 * the payload to an event queue that's embedded into its the callers context
 * structure.
 *
 * This assumes that the |ossl_event_queue_send()| will only return when the
 * event has been seen by all event handlers (subscribers to the queue).  If
 * the conditions are different, |buf| should be dynamically allocated, and
 * a freeing function should then be passed as the destructor argument to
 * |ossl_event_set0()|.
 */

int read_socket(struct reader_ctx_st *ctx, inte socket)
{
    struct ossl_event_st ev;
    unsigned char buf[2048];
    int ret;

    ret = read(socket, buf, sizeof(buf));
    if (ret < -1)
        return ret;
    ossl_event_set0(OSSL_EVENT_TYPE_READ, &ctx->event_queue,
                    NULL, buf, ret, NULL);
    return ossl_event_queue_send(ctx->event_queue, &ev);
}

```

Building recommendations
------------------------

Because we don't want to export internal symbols in our shared libraries,
the event queue and dispatcher implementation and all internal
implementations it needs will have to be included in the shared library
build of `libssl`.

That can be done like this in `ssl/build.info`:

``` text
SHARED_SOURCE[../libssl]=../crypto/event.c
```
