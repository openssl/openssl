/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/quic_cc.h"

typedef struct ossl_cc_dummy_st {
    char dummy;
} OSSL_CC_DUMMY;

static OSSL_CC_DATA *dummy_new(OSSL_PARAM *settings, OSSL_PARAM *options,
                               OSSL_PARAM *changeables)
{
    return OPENSSL_zalloc(sizeof(OSSL_CC_DUMMY));
}

static void dummy_free(OSSL_CC_DATA *cc)
{
    OPENSSL_free(cc);
}

static void dummy_reset(OSSL_CC_DATA *cc, int flags)
{

}

static int dummy_set_exemption(OSSL_CC_DATA *cc, int numpackets)
{
    return 1;
}

static int dummy_get_exemption(OSSL_CC_DATA *cc)
{
    return 0;
}

static int dummy_can_send(OSSL_CC_DATA *cc)
{
    return 1;
}

static uint64_t dummy_get_send_allowance(OSSL_CC_DATA *cc,
                                       OSSL_TIME time_since_last_send,
                                       int time_valid)
{
    return SIZE_MAX;
}

static uint64_t dummy_get_bytes_in_flight_max(OSSL_CC_DATA *cc)
{
    return SIZE_MAX;
}

static OSSL_TIME dummy_get_next_credit_time(OSSL_CC_DATA *cc_data)
{
    return ossl_time_infinite();
}

static int dummy_on_data_sent(OSSL_CC_DATA *cc,
                              uint64_t num_retransmittable_bytes)
{
    return 1;
}

static int dummy_on_data_invalidated(OSSL_CC_DATA *cc,
                                     uint64_t num_retransmittable_bytes)
{
    return 1;
}

static int dummy_on_data_acked(OSSL_CC_DATA *cc, OSSL_TIME time_now,
                               uint64_t last_pn_acked,
                               uint64_t num_retransmittable_bytes)
{
    return 1;
}

static void dummy_on_data_lost(OSSL_CC_DATA *cc,
                              uint64_t largest_pn_lost,
                              uint64_t largest_pn_sent,
                              uint64_t num_retransmittable_bytes,
                              int persistent_congestion)
{

}

static int dummy_on_spurious_congestion_event(OSSL_CC_DATA *cc)
{
    return 1;
}

const OSSL_CC_METHOD ossl_cc_dummy_method = {
    NULL,
    dummy_new,
    dummy_free,
    dummy_reset,
    dummy_set_exemption,
    dummy_get_exemption,
    dummy_can_send,
    dummy_get_send_allowance,
    dummy_get_bytes_in_flight_max,
    dummy_get_next_credit_time,
    dummy_on_data_sent,
    dummy_on_data_invalidated,
    dummy_on_data_acked,
    dummy_on_data_lost,
    dummy_on_spurious_congestion_event,
};
