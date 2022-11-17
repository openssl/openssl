/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QUIC_SF_LIST_H
# define OSSL_QUIC_SF_LIST_H

#include "internal/common.h"
#include "internal/uint_set.h"
#include "internal/quic_record_rx.h"

/*
 * Stream frame list
 * =================
 *
 * This data structure supports similar operations as uint64 set but
 * it has slightly different invariants and also carries data associated with
 * the ranges in the list.
 *
 * Operations:
 *   Insert frame (optimized insertion at the beginning and at the end).
 *   Iterated peek into the frame(s) from the beginning.
 *   Dropping frames from the beginning up to an offset (exclusive).
 *
 * Invariant: The frames in the list are sorted by the start and end bounds.
 * Invariant: There are no fully overlapping frames or frames that would
 *            be fully encompassed by another frame in the list.
 * Invariant: No frame has start > end.
 * Invariant: The range start is inclusive the end is exclusive to be
 *            able to mark an empty frame.
 * Invariant: The offset never points further than into the first frame.
 */
# ifndef OPENSSL_NO_QUIC

typedef struct stream_frame_st STREAM_FRAME;

typedef struct sframe_list_st {
    STREAM_FRAME  *head, *tail;
    /* Is the tail frame final. */
    unsigned int fin;
    /* Number of stream frames in the list. */
    size_t num_frames;
    /* Offset of data not yet dropped */
    uint64_t offset;
} SFRAME_LIST;

void ossl_sframe_list_init(SFRAME_LIST *fl);
void ossl_sframe_list_destroy(SFRAME_LIST *fl);
int ossl_sframe_list_insert(SFRAME_LIST *fl, UINT_RANGE *range,
                            OSSL_QRX_PKT *pkt,
                            const unsigned char *data, int fin);
int ossl_sframe_list_peek(const SFRAME_LIST *fl, void **iter,
                          UINT_RANGE *range, const unsigned char **data,
                          int *fin);
int ossl_sframe_list_drop_frames(SFRAME_LIST *fl, uint64_t limit);

# endif

#endif
