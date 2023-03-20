/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#ifndef OSSL_QUIC_CC_H
# define OSSL_QUIC_CC_H

#include "openssl/params.h"
#include "internal/time.h"

# ifndef OPENSSL_NO_QUIC

typedef struct ossl_cc_data_st *OSSL_CC_DATA;

typedef struct ossl_cc_method_st {
    void *dummy;

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
    uint64_t (*get_send_allowance)(OSSL_CC_DATA *ccdata,
                                   OSSL_TIME time_since_last_send,
                                   int time_valid);

    /*
     * Returns the maximum number of bytes allowed to be in flight.
     */
    uint64_t (*get_bytes_in_flight_max)(OSSL_CC_DATA *ccdata);

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
                        uint64_t num_retransmittable_bytes);

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
                               uint64_t num_retransmittable_bytes);

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
                         OSSL_TIME time_now,
                         uint64_t last_pn_acked,
                         uint64_t num_retransmittable_bytes);

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
                         uint64_t num_retransmittable_bytes,
                         int persistent_congestion);

    /*
     * To be called when all lost data from the previous call to
     * on_data_lost() was actually acknowledged.
     * This reverts the size of the congestion window to the state
     * before the on_data_lost() call.
     * Returns 1 if sending is unblocked, 0 otherwise.
     */
    int (*on_spurious_congestion_event)(OSSL_CC_DATA *ccdata);
} OSSL_CC_METHOD;

extern const OSSL_CC_METHOD ossl_cc_dummy_method;

# endif

#endif
