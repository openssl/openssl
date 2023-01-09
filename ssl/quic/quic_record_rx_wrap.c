/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "internal/refcount.h"
#include "internal/quic_record_rx_wrap.h"

OSSL_QRX_PKT_WRAP *ossl_qrx_pkt_wrap_new(OSSL_QRX_PKT *pkt)
{
    CRYPTO_RWLOCK *refcount_lock = NULL;
    OSSL_QRX_PKT_WRAP *res = NULL;

    if (pkt == NULL)
        return NULL;

#ifdef HAVE_ATOMICS
    refcount_lock = CRYPTO_THREAD_lock_new();
    if (refcount_lock == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_CRYPTO_LIB);
        return NULL;
    }
#endif

    if ((res = OPENSSL_zalloc(sizeof(*res))) == NULL) {
        CRYPTO_THREAD_lock_free(refcount_lock);
        return NULL;
    }

    res->pkt = pkt;
    res->handle = pkt->handle;
    res->references = 1;
    res->lock = refcount_lock;

    return res;
}

int ossl_qrx_pkt_wrap_up_ref(OSSL_QRX_PKT_WRAP *pkt_wrap)
{
    int ref = 0;

    if (pkt_wrap == NULL || pkt_wrap->pkt == NULL)
        return 0;
    CRYPTO_UP_REF(&pkt_wrap->references, &ref, pkt_wrap->lock);
    return 1;
}

void ossl_qrx_pkt_wrap_free(OSSL_QRX *qrx, OSSL_QRX_PKT_WRAP *pkt_wrap)
{
    int ref = 0;

    if (pkt_wrap == NULL)
        return;
    CRYPTO_DOWN_REF(&pkt_wrap->references, &ref, pkt_wrap->lock);
    if (ref > 0)
        return;
    ossl_qrx_release_pkt(qrx, pkt_wrap->handle);
    CRYPTO_THREAD_lock_free(pkt_wrap->lock);
    OPENSSL_free(pkt_wrap);
}
