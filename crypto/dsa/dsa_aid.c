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
#include "crypto/dsa.h"

#define ASN1_SEQUENCE 0x30
#define ASN1_OID 0x06

/* dsaWithSHA OIDs are of the form: (1 3 14 3 2 |n|) */
#define ENCODE_ALGORITHMIDENTIFIER_SHA(name, n)                         \
    static const unsigned char algorithmidentifier_##name##_der[] = {   \
        ASN1_SEQUENCE, 0x07,                                            \
          ASN1_OID, 0x05, 1 * 40 + 3, 14, 3, 2, n                       \
}

ENCODE_ALGORITHMIDENTIFIER_SHA(sha, 13);
ENCODE_ALGORITHMIDENTIFIER_SHA(sha1, 27);

/* dsaWithSHA OIDs are of the form: (2 16 840 1 101 3 4 3 |n|) */
#define ENCODE_ALGORITHMIDENTIFIER_SHAx(name, n)                        \
    static const unsigned char algorithmidentifier_##name##_der[] = {   \
        ASN1_SEQUENCE, 0x0b,                                            \
          ASN1_OID, 0x09, 2 * 40 + 16, 0x86, 0x48, 1, 101, 3, 4, 3, n   \
}

ENCODE_ALGORITHMIDENTIFIER_SHAx(sha224, 1);
ENCODE_ALGORITHMIDENTIFIER_SHAx(sha256, 2);
ENCODE_ALGORITHMIDENTIFIER_SHAx(sha384, 3);
ENCODE_ALGORITHMIDENTIFIER_SHAx(sha512, 4);
ENCODE_ALGORITHMIDENTIFIER_SHAx(sha3_224, 5);
ENCODE_ALGORITHMIDENTIFIER_SHAx(sha3_256, 6);
ENCODE_ALGORITHMIDENTIFIER_SHAx(sha3_384, 7);
ENCODE_ALGORITHMIDENTIFIER_SHAx(sha3_512, 8);

#define MD_CASE(name)                                                   \
    case NID_##name:                                                    \
        *len = sizeof(algorithmidentifier_##name##_der);                \
        return algorithmidentifier_##name##_der

const unsigned char *dsa_algorithmidentifier_encoding(int md_nid, size_t *len)
{
    switch (md_nid) {
        MD_CASE(sha);
        MD_CASE(sha1);
        MD_CASE(sha224);
        MD_CASE(sha256);
        MD_CASE(sha384);
        MD_CASE(sha512);
        MD_CASE(sha3_224);
        MD_CASE(sha3_256);
        MD_CASE(sha3_384);
        MD_CASE(sha3_512);
    default:
        return NULL;
    }
}
