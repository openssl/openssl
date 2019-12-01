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
#include "crypto/rsa.h"

#define ASN1_SEQUENCE 0x30
#define ASN1_OID 0x06

/*
 * -- RFC 2313
 * pkcs-1 OBJECT IDENTIFIER ::= {
 *     iso(1) member-body(2) US(840) rsadsi(113549) pkcs(1) 1
 * }
 */

/*
 * -- RFC 3279
 * md2WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 2 }
 * md5WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 4 }
 * sha1WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 5 }
 */
#define ENCODE_ALGORITHMIDENTIFIER_PKCS1(name, n)                       \
    static const unsigned char algorithmidentifier_##name##_der[] = {   \
        ASN1_SEQUENCE, 0x0b,                                            \
          ASN1_OID, 0x09, 1 * 40 + 2,  134, 72, 134, 247, 13, 1, 1, n   \
}
#ifndef FIPS_MODE
ENCODE_ALGORITHMIDENTIFIER_PKCS1(md2, 2);
ENCODE_ALGORITHMIDENTIFIER_PKCS1(md5, 4);
#endif
ENCODE_ALGORITHMIDENTIFIER_PKCS1(sha1, 5);

/*
 * -- RFC 4055
 * sha224WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 14 }
 * sha256WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 11 }
 * sha384WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 12 }
 * sha512WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 13 }
 */
ENCODE_ALGORITHMIDENTIFIER_PKCS1(sha224, 14);
ENCODE_ALGORITHMIDENTIFIER_PKCS1(sha256, 11);
ENCODE_ALGORITHMIDENTIFIER_PKCS1(sha384, 12);
ENCODE_ALGORITHMIDENTIFIER_PKCS1(sha512, 13);

/*
 * -- https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
 *
 * sigAlgs OBJECT IDENTIFIER ::= { 2 16 840 1 101 3 4 3 }
 *
 * id-rsassa-pkcs1-v1_5-with-sha3-224 ::= { sigAlgs 13 }
 * id-rsassa-pkcs1-v1_5-with-sha3-256 ::= { sigAlgs 14 }
 * id-rsassa-pkcs1-v1_5-with-sha3-384 ::= { sigAlgs 15 }
 * id-rsassa-pkcs1-v1_5-with-sha3-512 ::= { sigAlgs 16 }
 */
#define ENCODE_ALGORITHMIDENTIFIER_SIGALGS(name, n)                     \
    static const unsigned char algorithmidentifier_##name##_der[] = {   \
        ASN1_SEQUENCE, 0x0c,                                            \
          ASN1_OID, 0x0a, 1 * 40 + 2,  16, 134, 72, 1, 101, 3, 4, 3, n  \
}
ENCODE_ALGORITHMIDENTIFIER_SIGALGS(sha3_224, 13);
ENCODE_ALGORITHMIDENTIFIER_SIGALGS(sha3_256, 14);
ENCODE_ALGORITHMIDENTIFIER_SIGALGS(sha3_384, 15);
ENCODE_ALGORITHMIDENTIFIER_SIGALGS(sha3_512, 16);

#define MD_CASE(name)                                                   \
    case NID_##name:                                                    \
        *len = sizeof(algorithmidentifier_##name##_der);                \
        return algorithmidentifier_##name##_der

const unsigned char *rsa_algorithmidentifier_encoding(int md_nid, size_t *len)
{
    switch (md_nid) {
#ifndef FIPS_MODE
        MD_CASE(md2);
        MD_CASE(md5);
#endif
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
