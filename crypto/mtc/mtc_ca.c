/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * The identity core of a trusted Merkle Tree Certification Authority, built
 * from configured fields (section 7.1 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/).
 * See include/crypto/mtc_ca.h.
 */

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "crypto/ctype.h"
#include "crypto/mtc_ca.h"

OSSL_MTC_CA *ossl_mtc_ca_new(const uint8_t *ca_id, size_t ca_id_len,
    const EVP_MD *hash, uint64_t min_serial, EVP_PKEY *cosigner_pkey)
{
    OSSL_MTC_CA *ca = OPENSSL_zalloc(sizeof(*ca));

    if (ca == NULL)
        return NULL;

    ca->lock = CRYPTO_THREAD_lock_new();
    ca->ca_id = OPENSSL_memdup(ca_id, ca_id_len);
    /*
     * The references on hash and cosigner_pkey are taken last, so that until
     * they are recorded below there is nothing for ossl_mtc_ca_free() to
     * release.
     */
    if (ca->lock == NULL || ca->ca_id == NULL
        || !EVP_MD_up_ref((EVP_MD *)hash)) {
        ossl_mtc_ca_free(ca);
        return NULL;
    }
    ca->hash = (EVP_MD *)hash;
    if (!EVP_PKEY_up_ref(cosigner_pkey)) {
        ossl_mtc_ca_free(ca);
        return NULL;
    }

    ca->ca_id_len = ca_id_len;
    ca->min_serial = min_serial;
    ca->cosigner_pkey = cosigner_pkey;
    return ca;
}

void ossl_mtc_ca_free(OSSL_MTC_CA *ca)
{
    if (ca == NULL)
        return;
    OPENSSL_free(ca->ca_id);
    EVP_MD_free(ca->hash);
    EVP_PKEY_free(ca->cosigner_pkey);
    CRYPTO_THREAD_lock_free(ca->lock);
    OPENSSL_free(ca);
}

const uint8_t *ossl_mtc_ca_id(const OSSL_MTC_CA *ca, size_t *len)
{
    *len = ca->ca_id_len;
    return ca->ca_id;
}

const EVP_MD *ossl_mtc_ca_hash(const OSSL_MTC_CA *ca)
{
    return ca->hash;
}

EVP_PKEY *ossl_mtc_ca_cosigner_pkey(const OSSL_MTC_CA *ca)
{
    return ca->cosigner_pkey;
}
