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
#include "crypto/ec.h"

#define ASN1_SEQUENCE 0x30
#define ASN1_OID 0x06
#define OID_FIRST(a, b) a * 40 + b
#define DER_840() 0x86, 0x48    /* DER encoding of number 840 is 2 bytes */
#define DER_10045() 0xCE, 0x3D  /* DER encoding of number 10045 is 2 bytes */
#define SHA1_SZ 7
#define SHA2_SZ 8
#define SHA3_SZ 9

/*
 * -- RFC 3279
 * ansi-X9-62 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) 10045 }
 * id-ecSigType OBJECT IDENTIFIER ::= { ansi-X9-62 signatures(4) }
 *
 * ecdsa-with-SHA1 OBJECT IDENTIFIER ::= { id-ecSigType 1 }
 */
#define ENCODE_ALGORITHMIDENTIFIER_SHA1(name)                                  \
static const unsigned char algorithmidentifier_##name##_der[] = {              \
    ASN1_SEQUENCE, 2 + SHA1_SZ,                                                \
    ASN1_OID, SHA1_SZ, OID_FIRST(1, 2), DER_840(), DER_10045(), 4, 1           \
}

/*
 * -- RFC 5758
 *
 * ecdsa-with-SHA224 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 *      us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 1 }
 *
 * ecdsa-with-SHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 *      us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 2 }
 *
 * ecdsa-with-SHA384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 *      us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 3 }
 *
 * ecdsa-with-SHA512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 *      us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 4 }
 */
#define ENCODE_ALGORITHMIDENTIFIER_SHA2(name, n)                               \
static const unsigned char algorithmidentifier_##name##_der[] = {              \
    ASN1_SEQUENCE, 2 + SHA2_SZ,                                                \
    ASN1_OID, SHA2_SZ, OID_FIRST(1, 2), DER_840(), DER_10045(), 4, 3, n        \
}

/*
 * https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
 *
 * sigAlgs OBJECT IDENTIFIER ::= { 2 16 840 1 101 3 4 3 }
 *
 * id-ecdsa-with-sha3-224 ::= { sigAlgs 9 }
 * id-ecdsa-with-sha3-256 ::= { sigAlgs 10 }
 * id-ecdsa-with-sha3-384 ::= { sigAlgs 11 }
 * id-ecdsa-with-sha3-512 ::= { sigAlgs 12 }
 */
#define ENCODE_ALGORITHMIDENTIFIER_SHA3(name, n)                               \
static const unsigned char algorithmidentifier_##name##_der[] = {              \
    ASN1_SEQUENCE, 2 + SHA3_SZ,                                                \
    ASN1_OID, SHA3_SZ, OID_FIRST(2, 16), DER_840(), 1, 101, 3, 4, 3, n         \
}

ENCODE_ALGORITHMIDENTIFIER_SHA1(sha1);
ENCODE_ALGORITHMIDENTIFIER_SHA2(sha224, 1);
ENCODE_ALGORITHMIDENTIFIER_SHA2(sha256, 2);
ENCODE_ALGORITHMIDENTIFIER_SHA2(sha384, 3);
ENCODE_ALGORITHMIDENTIFIER_SHA2(sha512, 4);
ENCODE_ALGORITHMIDENTIFIER_SHA3(sha3_224, 9);
ENCODE_ALGORITHMIDENTIFIER_SHA3(sha3_256, 10);
ENCODE_ALGORITHMIDENTIFIER_SHA3(sha3_384, 11);
ENCODE_ALGORITHMIDENTIFIER_SHA3(sha3_512, 12);
/* TODO - Add SHAKE OIDS when they are standardized */

#define MD_CASE(name)                                                   \
    case NID_##name:                                                    \
        *len = sizeof(algorithmidentifier_##name##_der);                \
        return algorithmidentifier_##name##_der

const unsigned char *ecdsa_algorithmidentifier_encoding(int md_nid, size_t *len)
{
    switch (md_nid) {
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
