/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>

#include <openssl/objects.h>
#include "crypto/sm2.h"

#define ASN1_SEQUENCE 0x30
#define ASN1_OID 0x06
#define OID_FIRST(a, b) a * 40 + b
#define DER_156() 0x81, 0x1C    /* DER encoding of number 156 is 2 bytes */
#define DER_10197() 0xCF, 0x55  /* DER encoding of number 10197 is 2 bytes */
#define DER_501() 0x83, 0x75    /* DER encoding of number 501 is 2 bytes */
#define SM3_SZ 8

/* SM2-with-SM3 OID is of the form : (1 2 156 10197 1 501) */
#define ENCODE_ALGORITHMIDENTIFIER_SM3(name)                                  \
static const unsigned char algorithmidentifier_##name##_der[] = {             \
    ASN1_SEQUENCE, 2 + SM3_SZ,                                                \
    ASN1_OID, SM3_SZ, OID_FIRST(1, 2), DER_156(), DER_10197(), 1, DER_501()   \
}

/* not decided yet if SM2 should support other MDs */
ENCODE_ALGORITHMIDENTIFIER_SM3(sm3);

#define MD_CASE(name)                                                   \
    case NID_##name:                                                    \
        *len = sizeof(algorithmidentifier_##name##_der);                \
        return algorithmidentifier_##name##_der

const unsigned char *sm2_algorithmidentifier_encoding(int md_nid, size_t *len)
{
    switch (md_nid) {
        MD_CASE(sm3);
    default:
        return NULL;
    }
}
