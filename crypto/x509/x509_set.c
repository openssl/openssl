/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "internal/x509_int.h"

int X509_set_version(X509 *x, long version)
{
    if (x == NULL)
        return (0);
    if (version == 0) {
        ASN1_INTEGER_free(x->cert_info.version);
        x->cert_info.version = NULL;
        return (1);
    }
    if (x->cert_info.version == NULL) {
        if ((x->cert_info.version = ASN1_INTEGER_new()) == NULL)
            return (0);
    }
    return (ASN1_INTEGER_set(x->cert_info.version, version));
}

int X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial)
{
    ASN1_INTEGER *in;

    if (x == NULL)
        return 0;
    in = &x->cert_info.serialNumber;
    if (in != serial)
        return ASN1_STRING_copy(in, serial);
    return 1;
}

int X509_set_issuer_name(X509 *x, X509_NAME *name)
{
    if (x == NULL)
        return (0);
    return (X509_NAME_set(&x->cert_info.issuer, name));
}

int X509_set_subject_name(X509 *x, X509_NAME *name)
{
    if (x == NULL)
        return (0);
    return (X509_NAME_set(&x->cert_info.subject, name));
}

int X509_set_notBefore(X509 *x, const ASN1_TIME *tm)
{
    ASN1_TIME *in;

    if (x == NULL)
        return (0);
    in = x->cert_info.validity.notBefore;
    if (in != tm) {
        in = ASN1_STRING_dup(tm);
        if (in != NULL) {
            ASN1_TIME_free(x->cert_info.validity.notBefore);
            x->cert_info.validity.notBefore = in;
        }
    }
    return (in != NULL);
}

int X509_set_notAfter(X509 *x, const ASN1_TIME *tm)
{
    ASN1_TIME *in;

    if (x == NULL)
        return (0);
    in = x->cert_info.validity.notAfter;
    if (in != tm) {
        in = ASN1_STRING_dup(tm);
        if (in != NULL) {
            ASN1_TIME_free(x->cert_info.validity.notAfter);
            x->cert_info.validity.notAfter = in;
        }
    }
    return (in != NULL);
}

int X509_set_pubkey(X509 *x, EVP_PKEY *pkey)
{
    if (x == NULL)
        return (0);
    return (X509_PUBKEY_set(&(x->cert_info.key), pkey));
}

int X509_up_ref(X509 *x)
{
    int i;

    if (CRYPTO_atomic_add(&x->references, 1, &i, x->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("X509", x);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

long X509_get_version(const X509 *x)
{
    return ASN1_INTEGER_get(x->cert_info.version);
}

ASN1_TIME * X509_get_notBefore(const X509 *x)
{
    return x->cert_info.validity.notBefore;
}

ASN1_TIME *X509_get_notAfter(const X509 *x)
{
    return x->cert_info.validity.notAfter;
}

int X509_get_signature_type(const X509 *x)
{
    return EVP_PKEY_type(OBJ_obj2nid(x->sig_alg.algorithm));
}

X509_PUBKEY *X509_get_X509_PUBKEY(const X509 *x)
{
    return x->cert_info.key;
}

STACK_OF(X509_EXTENSION) *X509_get0_extensions(const X509 *x)
{
    return x->cert_info.extensions;
}

void X509_get0_uids(ASN1_BIT_STRING **piuid, ASN1_BIT_STRING **psuid, X509 *x)
{
    if (piuid != NULL)
        *piuid = x->cert_info.issuerUID;
    if (psuid != NULL)
        *psuid = x->cert_info.subjectUID;
}

X509_ALGOR *X509_get0_tbs_sigalg(X509 *x)
{
    return &x->cert_info.signature;
}
