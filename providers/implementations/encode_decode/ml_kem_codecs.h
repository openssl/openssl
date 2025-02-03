/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef PROV_ML_KEM_CODECS_H
# define PROV_ML_KEM_CODECS_H
# pragma once

# include <openssl/e_os2.h>
# include "crypto/ml_kem.h"
# include "prov/provider_ctx.h"

 /*-
  * The DER ASN.1 encoding of ML-KEM (and ML-DSA) public keys prepends 22 bytes
  * to the encoded public key:
  *
  * - 4 byte outer sequence tag and length
  * -  2 byte algorithm sequence tag and length
  * -    2 byte algorithm OID tag and length
  * -      9 byte algorithm OID (from NIST CSOR OID arc)
  * -  4 byte bit string tag and length
  * -    1 bitstring lead byte
  */
# define ML_KEM_SPKI_OVERHEAD   22
typedef struct {
    const uint8_t asn1_prefix[ML_KEM_SPKI_OVERHEAD];
} ML_KEM_SPKI_INFO;

/*-
 * For each parameter set we support a few PKCS#8 input formats, three
 * corresponding to the "either or both" variants of:
 *
 *  ML-KEM-PrivateKey ::= SEQUENCE {
 *    seed OCTET STRING SIZE (64) OPTIONAL,
 *    expandedKey [1] IMPLICIT OCTET STRING SIZE (1632 | 2400 | 3172) OPTIONAL }
 *   (WITH COMPONENTS {..., seed  PRESENT } |
 *    WITH COMPONENTS {..., expandedKey  PRESENT })
 *
 * and two more for historical OQS encodings.
 *
 * - OQS private key: OCTET STRING
 * - OQS private + public key: OCTET STRING
 *   (The public key is ignored, just as with PKCS#8 v2.)
 *
 * An offset of zero means that particular field is absent.
 */
typedef struct {
    const char *p8_name;
    size_t p8_bytes;
    uint32_t p8_magic;
    uint16_t seed_magic;
    size_t seed_offset;
    size_t seed_length;
    uint32_t priv_magic;
    size_t priv_offset;
    size_t priv_length;
    size_t pub_offset;
    size_t pub_length;
} ML_KEM_PKCS8_INFO;

typedef struct {
    const ML_KEM_SPKI_INFO *spki_info;
    const ML_KEM_PKCS8_INFO *pkcs8_info;
} ML_KEM_CODEC;

typedef struct {
    const ML_KEM_PKCS8_INFO *vp8_entry;
    int vp8_pref;
} ML_KEM_PKCS8_PREF;

__owur
ML_KEM_KEY *ossl_ml_kem_d2i_PUBKEY(const uint8_t *pubenc, int publen,
                                   int evp_type, PROV_CTX *provctx,
                                   const char *propq);
__owur
ML_KEM_KEY *ossl_ml_kem_d2i_PKCS8(const uint8_t *prvenc, int prvlen,
                                  int evp_type, PROV_CTX *provctx,
                                  const char *propq);
__owur
int ossl_ml_kem_key_to_text(BIO *out, const ML_KEM_KEY *key, int selection);
__owur
__owur
int ossl_ml_kem_i2d_pubkey(const ML_KEM_KEY *key, unsigned char **out);
__owur
__owur
int ossl_ml_kem_i2d_prvkey(const ML_KEM_KEY *key, unsigned char **out,
                           PROV_CTX *provctx);

#endif  /* PROV_ML_KEM_CODECS_H */
