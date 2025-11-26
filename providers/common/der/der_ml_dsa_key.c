/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * DSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include "internal/packet.h"
#include "prov/der_ml_dsa.h"
#include "prov/der_pq_dsa.h"
#include "prov/der_digests.h"

#define IS_MD(algname, name, hashsz)                                           \
(EVP_MD_is_a(md, algname)) {                                                   \
    *oid = ossl_der_oid_id_##name;                                             \
    *oidlen = sizeof(ossl_der_oid_id_##name);                                  \
    *sz = hashsz;                                                              \
}

int ossl_DER_w_algorithmIdentifier_ML_DSA(WPACKET *pkt, int tag, ML_DSA_KEY *key)
{
    const uint8_t *alg;
    size_t len;
    const char *name = ossl_ml_dsa_key_get_name(key);

    if (OPENSSL_strcasecmp(name, "ML-DSA-44") == 0) {
        alg = ossl_der_oid_id_ml_dsa_44;
        len = sizeof(ossl_der_oid_id_ml_dsa_44);
    } else if (OPENSSL_strcasecmp(name, "ML-DSA-65") == 0) {
        alg = ossl_der_oid_id_ml_dsa_65;
        len = sizeof(ossl_der_oid_id_ml_dsa_65);
    } else if (OPENSSL_strcasecmp(name, "ML-DSA-87") == 0) {
        alg = ossl_der_oid_id_ml_dsa_87;
        len = sizeof(ossl_der_oid_id_ml_dsa_87);
    } else {
        return 0;
    }
    return ossl_DER_w_begin_sequence(pkt, tag)
        /* No parameters */
        && ossl_DER_w_precompiled(pkt, -1, alg, len)
        && ossl_DER_w_end_sequence(pkt, tag);
}

int ossl_der_oid_pq_dsa_prehash_digest(const EVP_MD *md,
                                       const uint8_t **oid, size_t *oidlen,
                                       size_t *sz)
{
    if IS_MD("SHAKE-256", shake256, 64)
    else if IS_MD("SHAKE-128", shake128, 32)
    else if IS_MD("SHA2-224", sha224, 28)
    else if IS_MD("SHA2-256", sha256, 32)
    else if IS_MD("SHA2-384", sha384, 48)
    else if IS_MD("SHA2-512", sha512, 64)
    else if IS_MD("SHA3-224", sha3_224, 28)
    else if IS_MD("SHA3-256", sha3_256, 32)
    else if IS_MD("SHA3-384", sha3_384, 48)
    else if IS_MD("SHA3-512", sha3_512, 64)
    else
        return 0;
    return 1;
}
