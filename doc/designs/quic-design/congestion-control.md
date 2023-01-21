Congestion control API design
=============================

This is mostly inspired by the MSQUIC congestion control API
as it was the most isolated one among the libraries.

The API is designed in a way to be later easily transformed into a
a fetchable implementation API.

The API is centered around two structures - the `OSSL_CC_METHOD`
structure holding the API calls into the congestion control module
and `OSSL_CC_DATA` opaque type that holds the data of needed
for the operation of the module.

Most of the information when the functions of the API are
supposed to be called and how the API is designed to operate
should be clear from the comments for the individual
functions in [Appendix A](#appendix-a).

Changeables
-----------

As some parameters that the congestion control algorithm needs might
be updated during the lifetime of the connection these parameters
are called changeables.

The CC implementation will save the pointers to these parameters'
data and will use the current value of the data at the pointer when
it needs to recalculate the allowance and whether the sending is
blocked or not.

Some examples of changeables

 - `payload_length` - the maximum length of payload that can be sent
   in a single UDP packet (not counting UDP and IP headers).
 - `smoothed_rtt` - the current round trip time of the connection
   as computed from the acked packets.
 - `rtt_variance` - the variance of the `smoothed_rtt` value.

Thread handling
---------------

The `OSSL_CC_DATA` is created with the `new` function per each
connection. The expectation is that there is only a single thread
accessing the `ccdata` which should not be a limitation as the calls
into the module will be done from the packetizer layer of the QUIC
connection handling and there the eventual writes from multiple threads
handling individual streams of the connection have to be synchronized
already to create the packets.

Congestion event handling
-------------------------

The congestion state of a connection can change only after some event
happens - i.e., a packet is considered lost meaning the `on_data_lost()`
is called, or an ack arrives for a packet causing calls to
`on_data_acked()` or `on_spurious_congestion_event()` functions.
The congestion control does not produce any timer events by itself.

Exemptions
----------

To facilitate probing and to avoid having to always special-case
probing packets when considering congestion on sending, the
`set_exemption()` function allows setting a number of packets that are
allowed to be sent even when forbidden by the eventual congestion state.

The exemptions must be used if and only if a packet (or multiple packets)
has to be sent as required by the protocol regardless of the congestion state.

Paths
-----

Initially the design expects that only a single path per-connection is
actively sending data. In future when multiple active paths sending data
shall be supported the instances of `OSSL_CC_DATA` would be per-path.

There might need to be further adjustments needed in that case. However
at least initially this API is intended to be internal to the
OpenSSL library allowing any necessary changes of the API.

Appendix A
----------

Proposed header file with comments explaining the individual
functions. The API is meant to be internal initially so the method
accessors to set the individual functions will be added later once
the API is public. Alternatively this might be also implemented
as fetchable dispatch API.

```C
/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>

typedef struct ossl_cc_method_st OSSL_CC_METHOD;
/*
 * An OSSL_CC_DATA is an externally defined opaque pointer holding
 * the internal data of the congestion control method
 */
typedef struct ossl_cc_data_st OSSL_CC_DATA;

/*
 * Once this becomes public API then we will need functions to create and
 * free an OSSL_CC_METHOD, as well as functions to get/set the various
 * function pointers....unless we make it fetchable.
 */
struct ossl_cc_method_st {
    /*
     * Create a new OSSL_CC_DATA object to handle the congestion control
     * calculations.
     *
     * |settings| are mandatory settings that will cause the
     * new() call to fail if they are not understood).
     * |options| are optional settings that will not
     * cause the new() call to fail if they are not understood.
     * |changeables| contain additional parameters that the congestion
     * control algorithms need that can be updated during the
     * connection lifetime - for example size of the datagram payload.
     * To avoid calling a function with OSSL_PARAM array every time
     * these parameters are changed the addresses of these param
     * values are considered permanent and the values can be updated
     * any time.
     */
    OSSL_CC_DATA *(*new)(OSSL_PARAM *settings, OSSL_PARAM *options,
                         OSSL_PARAM *changeables);

    /*
     * Release the OSSL_CC_DATA.
     */
    void (*free)(OSSL_CC_DATA *ccdata);

    /*
     * Reset the congestion control state.
     * |flags| to support different level of reset (partial/full).
     */
    void (*reset)(OSSL_CC_DATA *ccdata, int flags);

    /*
     * Set number of packets exempted from CC - used for probing
     * |numpackets| is a small value (2).
     * Returns 0 on error, 1 otherwise.
     */
    int (*set_exemption)(OSSL_CC_DATA *ccdata, int numpackets);

    /*
     * Get current number of packets exempted from CC.
     * Returns negative value on error, the number otherwise.
     */
    int (*get_exemption)(OSSL_CC_DATA *ccdata);

    /*
     * Returns 1 if sending is allowed, 0 otherwise.
     */
    int (*can_send)(OSSL_CC_DATA *ccdata);

    /*
     * Returns number of bytes allowed to be sent.
     * |time_since_last_send| is time since last send operation
     * in microseconds.
     * |time_valid| is 1 if the |time_since_last_send| holds
     * a meaningful value, 0 otherwise.
     */
    size_t (*get_send_allowance)(OSSL_CC_DATA *ccdata,
                                 uint64_t time_since_last_send,
                                 int time_valid);

    /*
     * Returns the maximum number of bytes allowed to be in flight.
     */
    size_t (*get_bytes_in_flight_max)(OSSL_CC_DATA *ccdata);

    /*
     * Returns the next time at which the CC will release more budget for
     * sending, or ossl_time_infinite().
     */
    OSSL_TIME (*get_next_credit_time)(OSSL_CC_DATA *ccdata);

    /*
     * To be called when a packet with retransmittable data was sent.
     * |num_retransmittable_bytes| is the number of bytes sent
     * in the packet that are retransmittable.
     * Returns 1 on success, 0 otherwise.
     */
    int (*on_data_sent)(OSSL_CC_DATA *ccdata,
                        size_t num_retransmittable_bytes);

    /*
     * To be called when retransmittable data was invalidated.
     * I.E. they are not considered in-flight anymore but
     * are neither acknowledged nor lost. In particular used when
     * 0RTT data was rejected.
     * |num_retransmittable_bytes| is the number of bytes
     * of the invalidated data.
     * Returns 1 if sending is unblocked (can_send returns 1), 0
     * otherwise.
     */
    int (*on_data_invalidated)(OSSL_CC_DATA *ccdata,
                               size_t num_retransmittable_bytes);

    /*
     * To be called when sent data was acked.
     * |time_now| is current time in microseconds.
     * |largest_pn_acked| is the largest packet number of the acked
     * packets.
     * |num_retransmittable_bytes| is the number of retransmittable
     * packet bytes that were newly acked.
     * Returns 1 if sending is unblocked (can_send returns 1), 0
     * otherwise.
     */
    int (*on_data_acked)(OSSL_CC_DATA *ccdata,
                         uint64_t time_now,
                         uint64_t last_pn_acked,
                         size_t num_retransmittable_bytes);

    /*
     * To be called when sent data is considered lost.
     * |largest_pn_lost| is the largest packet number of the lost
     * packets.
     * |largest_pn_sent| is the largest packet number sent on this
     * connection.
     * |num_retransmittable_bytes| is the number of retransmittable
     * packet bytes that are newly considered lost.
     * |persistent_congestion| is 1 if the congestion is considered
     * persistent (see RFC 9002 Section 7.6), 0 otherwise.
     */
    void (*on_data_lost)(OSSL_CC_DATA *ccdata,
                         uint64_t largest_pn_lost,
                         uint64_t largest_pn_sent,
                         size_t num_retransmittable_bytes,
                         int persistent_congestion);

    /*
     * To be called when all lost data from the previous call to
     * on_data_lost() was actually acknowledged.
     * This reverts the size of the congestion window to the state
     * before the on_data_lost() call.
     * Returns 1 if sending is unblocked, 0 otherwise.
     */
    int (*on_spurious_congestion_event)(OSSL_CC_DATA *ccdata);
};
```
