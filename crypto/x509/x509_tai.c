/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * The trust anchor state of an X509_STORE, read by libssl to build the
 * trust_anchors extension.  libssl builds its own copy of this file (see
 * ssl/build.info), as libcrypto does not export these functions.
 */

#include <openssl/x509.h>

#include "crypto/x509.h"
#include "internal/packet.h"
#include "x509_local.h"

STACK_OF(OSSL_MTC_CA) *ossl_x509_store_get0_mtc_cas(const X509_STORE *store)
{
    return store == NULL ? NULL : store->mtc_cas;
}

int ossl_x509_store_has_trust_anchor_ids(X509_STORE *store)
{
    int ret;

    if (store == NULL || !CRYPTO_THREAD_read_lock(store->lock))
        return 0;
    ret = store->trust_anchor_ids_len > 0;
    CRYPTO_THREAD_unlock(store->lock);
    return ret;
}

int ossl_x509_store_put_trust_anchor_ids(X509_STORE *store, WPACKET *pkt)
{
    int ret;

    if (store == NULL)
        return 1;
    if (!CRYPTO_THREAD_read_lock(store->lock))
        return 0;
    ret = WPACKET_memcpy(pkt, store->trust_anchor_ids,
        store->trust_anchor_ids_len);
    CRYPTO_THREAD_unlock(store->lock);
    return ret;
}
