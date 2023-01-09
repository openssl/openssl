/*
* Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
*/
#include "internal/common.h"
#include "internal/time.h"
#include "internal/quic_stream.h"
#include "internal/quic_sf_list.h"

struct quic_rstream_st {
    SFRAME_LIST fl;
    QUIC_RXFC *rxfc;
    OSSL_STATM *statm;
};

QUIC_RSTREAM *ossl_quic_rstream_new(OSSL_QRX *qrx, QUIC_RXFC *rxfc,
                                    OSSL_STATM *statm)
{
    QUIC_RSTREAM *ret = OPENSSL_malloc(sizeof(*ret));

    if (ret == NULL)
        return NULL;

    ossl_sframe_list_init(&ret->fl, qrx);
    ret->rxfc = rxfc;
    ret->statm = statm;
    return ret;
}

void ossl_quic_rstream_free(QUIC_RSTREAM *qrs)
{
    ossl_sframe_list_destroy(&qrs->fl);
    OPENSSL_free(qrs);
}

int ossl_quic_rstream_queue_data(QUIC_RSTREAM *qrs, OSSL_QRX_PKT_WRAP *pkt_wrap,
                                 uint64_t offset,
                                 const unsigned char *data, uint64_t data_len,
                                 int fin)
{
    UINT_RANGE range;

    range.start = offset;
    range.end = offset + data_len;

    return ossl_sframe_list_insert(&qrs->fl, &range, pkt_wrap, data, fin);
}

static int read_internal(QUIC_RSTREAM *qrs, unsigned char *buf, size_t size,
                         size_t *readbytes, int *fin, int drop)
{
    void *iter = NULL;
    UINT_RANGE range;
    const unsigned char *data;
    uint64_t offset = 0;
    size_t readbytes_ = 0;
    int fin_ = 0, ret = 1;

    while (ossl_sframe_list_peek(&qrs->fl, &iter, &range, &data, &fin_)) {
        size_t l = (size_t)(range.end - range.start);

        if (l > size)
            l = size;
        memcpy(buf, data, l);
        offset = range.start + l;
        size -= l;
        buf += l;
        readbytes_ += l;
        if (size == 0)
            break;
    }

    if (drop && offset != 0)
        ret = ossl_sframe_list_drop_frames(&qrs->fl, offset);

    if (ret) {
        *readbytes = readbytes_;
        *fin = fin_;
    }

    return ret;
}

int ossl_quic_rstream_read(QUIC_RSTREAM *qrs, unsigned char *buf, size_t size,
                           size_t *readbytes, int *fin)
{
    OSSL_TIME rtt;

    if (qrs->statm != NULL) {
        OSSL_RTT_INFO rtt_info;

        ossl_statm_get_rtt_info(qrs->statm, &rtt_info);
        rtt = rtt_info.smoothed_rtt;
    } else {
        rtt = ossl_time_zero();
    }

    if (!read_internal(qrs, buf, size, readbytes, fin, 1))
        return 0;

    if (qrs->rxfc != NULL
        && !ossl_quic_rxfc_on_retire(qrs->rxfc, *readbytes, rtt))
        return 0;

    return 1;
}

int ossl_quic_rstream_peek(QUIC_RSTREAM *qrs, unsigned char *buf, size_t size,
                           size_t *readbytes, int *fin)
{
    return read_internal(qrs, buf, size, readbytes, fin, 0);
}

int ossl_quic_rstream_available(QUIC_RSTREAM *qrs, size_t *avail, int *fin)
{
    void *iter = NULL;
    UINT_RANGE range;
    const unsigned char *data;
    uint64_t avail_ = 0;

    while (ossl_sframe_list_peek(&qrs->fl, &iter, &range, &data, fin))
        avail_ += range.end - range.start;

#if SIZE_MAX < UINT64_MAX
    *avail = avail_ > SIZE_MAX ? SIZE_MAX : (size_t)avail_;
#else
    *avail = (size_t)avail_;
#endif
    return 1;
}
