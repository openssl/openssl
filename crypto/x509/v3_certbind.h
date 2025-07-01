/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_V3_CERTBIND_H
#define OPENSSL_V3_CERTBIND_H

#include <openssl/opensslconf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RFC 9763 Related Certificate Implementation */

/* ASN.1 structure definitions */
typedef struct CERT_ID_st {
    X509_NAME *issuer;
    ASN1_INTEGER *serialNumber;
} CERT_ID;

typedef struct BINARY_TIME_st {
    ASN1_OCTET_STRING *time;
} BINARY_TIME;

typedef struct UNIFORM_RESOURCE_IDENTIFIERS_st {
    STACK_OF(ASN1_STRING) *uris;
} UNIFORM_RESOURCE_IDENTIFIERS;

typedef struct REQUESTER_CERTIFICATE_st {
    CERT_ID *certID;
    BINARY_TIME *requestTime;
    UNIFORM_RESOURCE_IDENTIFIERS *locationInfo;
    ASN1_BIT_STRING *signature;
} REQUESTER_CERTIFICATE;

typedef struct RELATED_CERTIFICATE_st {
    X509_ALGOR *hashAlgorithm;
    ASN1_OCTET_STRING *hashValue;
} RELATED_CERTIFICATE;

/* Function declarations */

/* Add relatedCertRequest attribute to CSR */
int add_related_cert_request_to_csr(X509_REQ *req, EVP_PKEY *pkey, X509 *related_cert, 
                                   const char *uri, const EVP_MD *hash_alg);

/* Add RelatedCertificate extension to X.509 certificate */
int add_related_certificate_extension(X509 *cert, X509 *related_cert, const EVP_MD *hash_alg);

/* Verify RelatedCertificate extension */
int verify_related_certificate_extension(X509 *cert, X509 *related_cert);

/* Extract RelatedCertificate extension from certificate */
RELATED_CERTIFICATE *get_related_certificate_extension(X509 *cert);

/* Verify relatedCertRequest attribute in CSR */
int verify_related_cert_request(X509_REQ *req);

/* Print RelatedCertificate extension */
int print_related_certificate_extension(BIO *bio, X509 *cert, int indent);

/* Print relatedCertRequest attribute from CSR */
int print_related_cert_request(BIO *bio, X509_REQ *req, int indent);

/* Initialize RelatedCertificate extension support */
int v3_certbind_init(void);

/* ASN.1 function declarations */
DECLARE_ASN1_FUNCTIONS(CERT_ID)
DECLARE_ASN1_FUNCTIONS(BINARY_TIME)
DECLARE_ASN1_FUNCTIONS(UNIFORM_RESOURCE_IDENTIFIERS)
DECLARE_ASN1_FUNCTIONS(REQUESTER_CERTIFICATE)
DECLARE_ASN1_FUNCTIONS(RELATED_CERTIFICATE)

#ifdef __cplusplus
}
#endif

#endif /* OPENSSL_V3_CERTBIND_H */ 