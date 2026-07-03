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

#include <string.h>

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
    size_t i;

    if (ca == NULL)
        return;
    for (i = 0; i < ca->cosigner_count; i++) {
        OPENSSL_free(ca->cosigners[i].id);
        OPENSSL_free(ca->cosigners[i].sig_name);
        EVP_PKEY_free(ca->cosigners[i].pkey);
    }
    OPENSSL_free(ca->cosigners);
    OPENSSL_free(ca->revoked);
    OPENSSL_free(ca->ca_id);
    EVP_MD_free(ca->hash);
    EVP_PKEY_free(ca->cosigner_pkey);
    CRYPTO_THREAD_lock_free(ca->lock);
    OPENSSL_free(ca);
}

int ossl_mtc_ca_add_cosigner(OSSL_MTC_CA *ca, const uint8_t *id, size_t id_len,
    const char *sig_name, EVP_PKEY *pkey)
{
    OSSL_MTC_COSIGNER *tmp, *entry;
    uint8_t *id_copy = NULL;
    char *sig_copy = NULL;
    size_t i;
    int ret = 0;

    if (!CRYPTO_THREAD_write_lock(ca->lock))
        return 0;

    /* Cosigner IDs must be distinct (5.3): reject the CA ID and duplicates. */
    if (id_len == ca->ca_id_len && memcmp(id, ca->ca_id, id_len) == 0)
        goto out;
    for (i = 0; i < ca->cosigner_count; i++) {
        if (ca->cosigners[i].id_len == id_len
            && memcmp(ca->cosigners[i].id, id, id_len) == 0)
            goto out;
    }

    id_copy = OPENSSL_memdup(id, id_len);
    if (id_copy == NULL)
        goto out;

    sig_copy = OPENSSL_strdup(sig_name);
    if (sig_copy == NULL)
        goto out;

    tmp = OPENSSL_realloc_array(ca->cosigners, ca->cosigner_count + 1,
        sizeof(*ca->cosigners));
    if (tmp == NULL)
        goto out;
    ca->cosigners = tmp;

    if (!EVP_PKEY_up_ref(pkey))
        goto out;

    entry = &ca->cosigners[ca->cosigner_count];
    entry->id = id_copy;
    entry->id_len = id_len;
    entry->sig_name = sig_copy;
    entry->pkey = pkey;
    ca->cosigner_count++;
    id_copy = NULL;
    sig_copy = NULL;
    ret = 1;
out:
    OPENSSL_free(id_copy);
    OPENSSL_free(sig_copy);
    CRYPTO_THREAD_unlock(ca->lock);
    return ret;
}

int ossl_mtc_ca_add_revoked_range(OSSL_MTC_CA *ca, uint64_t start, uint64_t end)
{
    OSSL_MTC_SERIAL_RANGE *tmp;
    int ret = 0;

    if (start >= end) /* the half-open range must be non-empty */
        return 0;

    if (!CRYPTO_THREAD_write_lock(ca->lock))
        return 0;

    tmp = OPENSSL_realloc_array(ca->revoked, ca->revoked_count + 1,
        sizeof(*ca->revoked));
    if (tmp == NULL)
        goto out;
    ca->revoked = tmp;

    ca->revoked[ca->revoked_count].start = start;
    ca->revoked[ca->revoked_count].end = end;
    ca->revoked_count++;
    ret = 1;
out:
    CRYPTO_THREAD_unlock(ca->lock);
    return ret;
}

int ossl_mtc_ca_serial_is_revoked(const OSSL_MTC_CA *ca, uint64_t serial)
{
    size_t i;
    int revoked = 0;

    /* If the lock cannot be taken, fail closed by reporting revoked. */
    if (!CRYPTO_THREAD_read_lock(ca->lock))
        return 1;

    if (serial < ca->min_serial) { /* implied revoked range [0, min_serial) */
        revoked = 1;
    } else {
        for (i = 0; i < ca->revoked_count; i++) {
            if (serial >= ca->revoked[i].start && serial < ca->revoked[i].end) {
                revoked = 1;
                break;
            }
        }
    }

    CRYPTO_THREAD_unlock(ca->lock);
    return revoked;
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
