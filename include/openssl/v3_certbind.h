#ifndef REQUESTER_CERTIFICATE_H
#define REQUESTER_CERTIFICATE_H

#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

/* Définition complète de CERT_ID */
typedef struct cert_id_st {
    X509_NAME *issuer;
    ASN1_INTEGER *serialNumber;
} CERT_ID;

DECLARE_ASN1_FUNCTIONS(CERT_ID)

/* Définition complète de REQUESTER_CERTIFICATE */
typedef struct requester_certificate_st {
    CERT_ID *certID;
    ASN1_OCTET_STRING *requestTime;
    ASN1_IA5STRING *locationInfo;
    ASN1_BIT_STRING *signature;
} REQUESTER_CERTIFICATE;

DECLARE_ASN1_FUNCTIONS(REQUESTER_CERTIFICATE)

#endif
