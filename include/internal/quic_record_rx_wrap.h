/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QUIC_RECORD_RX_WRAP_H
# define OSSL_QUIC_RECORD_RX_WRAP_H

# include <openssl/crypto.h>
# include "internal/refcount.h"
# include "internal/quic_record_rx.h"

/*
 * OSSL_QRX_PKT handle wrapper for counted references
 * ==================================================
 *
 * When OSSL_QRX_PKT handles need to be put "in the wild", there may be
 * multiple references, which must be accounted for so that the OSSL_QRX_PKT
 * data isn't prematurely destroyed.
 * The OSSL_QRX_PKT itself is less important for reference counting, since
 * its handle contains references to all important data.
 *
 * The wrapper is created by ossl_quic_depacketize().
 * Consumers must call ossl_qrx_pkt_wrap_up_ref() as they grab a reference,
 * and must call ossl_qrx_pkt_wrap_release() when letting go of a reference.
 */

typedef struct ossl_qrx_pkt_wrap_st {
    void *handle;                /* This is a copy of |pkt->handle| */
    OSSL_QRX_PKT *pkt;
    CRYPTO_REF_COUNT references;
    CRYPTO_RWLOCK *lock;         /* For reference counting without atomic */
} OSSL_QRX_PKT_WRAP;

OSSL_QRX_PKT_WRAP *ossl_qrx_pkt_wrap_new(OSSL_QRX_PKT *pkt);
int ossl_qrx_pkt_wrap_up_ref(OSSL_QRX_PKT_WRAP *pkt_wrap);
void ossl_qrx_pkt_wrap_free(OSSL_QRX *qrx, OSSL_QRX_PKT_WRAP *pkt_wrap);

#endif
