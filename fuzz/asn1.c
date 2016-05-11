/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/*
 * Fuzz ASN.1 parsing for various data structures. Specify which on the
 * command line:
 *
 * asn1 <data structure>
 */

#include <stdio.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/ec.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs12.h>
#include <openssl/ts.h>
#include <openssl/x509v3.h>
#include "fuzzer.h"

static const ASN1_ITEM *item_type;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    const char *cmd;
    OPENSSL_assert(*argc > 1);

    cmd = (*argv)[1];
    (*argv)[1] = (*argv)[0];
    ++*argv;
    --*argc;

    // TODO: make this work like d2i_test.c does, once its decided what the
    // common scheme is!
#define Y(t)  if (!strcmp(cmd, #t)) item_type = ASN1_ITEM_rptr(t)
#define X(t)  else Y(t)

    Y(ASN1_SEQUENCE);
    X(AUTHORITY_INFO_ACCESS);
    X(BIGNUM);
    X(ECPARAMETERS);
    X(ECPKPARAMETERS);
    X(GENERAL_NAME);
    X(GENERAL_SUBTREE);
    X(NAME_CONSTRAINTS);
    X(OCSP_BASICRESP);
    X(OCSP_RESPONSE);
    X(PKCS12);
    X(PKCS12_AUTHSAFES);
    X(PKCS12_SAFEBAGS);
    X(PKCS7);
    X(PKCS7_ATTR_SIGN);
    X(PKCS7_ATTR_VERIFY);
    X(PKCS7_DIGEST);
    X(PKCS7_ENC_CONTENT);
    X(PKCS7_ENCRYPT);
    X(PKCS7_ENVELOPE);
    X(PKCS7_RECIP_INFO);
    X(PKCS7_SIGN_ENVELOPE);
    X(PKCS7_SIGNED);
    X(PKCS7_SIGNER_INFO);
    X(POLICY_CONSTRAINTS);
    X(POLICY_MAPPINGS);
    X(SXNET);
    //X(TS_RESP);  want to do this, but type is hidden, however d2i exists...
    X(X509);
    X(X509_CRL);
    else
        OPENSSL_assert(!"Bad type");

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
    const uint8_t *b = buf;
    ASN1_VALUE *o = ASN1_item_d2i(NULL, &b, len, item_type);
    ASN1_item_free(o, item_type);
    return 0;
}
