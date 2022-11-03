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
    (void)settings;
    (void)options;
    (void)changeables;
    return OPENSSL_zalloc(sizeof(OSSL_CC_DUMMY));
}

static void dummy_free(OSSL_CC_DATA *cc)
{
    OPENSSL_free(cc);
}

static void dummy_reset(OSSL_CC_DATA *cc, int flags)
{
    (void)cc;
    (void)flags;
}

static int dummy_set_exemption(OSSL_CC_DATA *cc, int numpackets)
{
    (void)cc;
    (void)numpackets;
    return 1;
}

static int dummy_get_exemption(OSSL_CC_DATA *cc)
{
    (void)cc;
    return 0;
}

static int dummy_can_send(OSSL_CC_DATA *cc)
{
    (void)cc;
    return 1;
}

static uint64_t dummy_get_send_allowance(OSSL_CC_DATA *cc,
                                       OSSL_TIME time_since_last_send,
                                       int time_valid)
{
    (void)cc;
    (void)time_since_last_send;
    (void)time_valid;
    return SIZE_MAX;
}

static uint64_t dummy_get_bytes_in_flight_max(OSSL_CC_DATA *cc)
{
    (void)cc;
    return SIZE_MAX;
}

static int dummy_on_data_sent(OSSL_CC_DATA *cc,
                              uint64_t num_retransmittable_bytes)
{
    (void)cc;
    (void)num_retransmittable_bytes;
    return 1;
}

static int dummy_on_data_invalidated(OSSL_CC_DATA *cc,
                                     uint64_t num_retransmittable_bytes)
{
    (void)cc;
    (void)num_retransmittable_bytes;
    return 1;
}

static int dummy_on_data_acked(OSSL_CC_DATA *cc, OSSL_TIME time_now,
                               uint64_t last_pn_acked,
                               uint64_t num_retransmittable_bytes)
{
    (void)cc;
    (void)time_now;
    (void)last_pn_acked;
    (void)num_retransmittable_bytes;
    return 1;
}

static void dummy_on_data_lost(OSSL_CC_DATA *cc,
                              uint64_t largest_pn_lost,
                              uint64_t largest_pn_sent,
                              uint64_t num_retransmittable_bytes,
                              int persistent_congestion)
{
    (void)cc;
    (void)largest_pn_lost;
    (void)largest_pn_sent;
    (void)num_retransmittable_bytes;
    (void)persistent_congestion;    
}

static int dummy_on_spurious_congestion_event(OSSL_CC_DATA *cc)
{
    (void)cc;
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
    dummy_on_data_sent,
    dummy_on_data_invalidated,
    dummy_on_data_acked,
    dummy_on_data_lost,
    dummy_on_spurious_congestion_event,
};
