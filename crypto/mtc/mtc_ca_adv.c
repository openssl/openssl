/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * A Merkle Tree CA's trust anchors advertisement, read by libssl to build
 * the trust_anchors extension.  libssl builds its own copy of this file
 * (see ssl/build.info), as libcrypto does not export it.
 */

#include <openssl/crypto.h>

#include "crypto/mtc_ca.h"
#include "internal/packet.h"

int ossl_mtc_ca_put_advertised_ids(const OSSL_MTC_CA *ca, WPACKET *pkt)
{
    int ret;

    if (!CRYPTO_THREAD_read_lock(ca->lock))
        return 0;
    ret = WPACKET_memcpy(pkt, ca->advertised_ids, ca->advertised_ids_len);
    CRYPTO_THREAD_unlock(ca->lock);
    return ret;
}
