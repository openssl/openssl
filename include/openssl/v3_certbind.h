#ifndef V3_CERTBIND_H
#define V3_CERTBIND_H

#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#ifdef __cplusplus
extern "C" {
#endif

// Structure ASN.1 : CertID ::= SEQUENCE { issuer Name, serialNumber INTEGER }
typedef struct cert_id_st {
    X509_NAME *issuer;
    ASN1_INTEGER *serialNumber;
} CERT_ID;

DECLARE_ASN1_FUNCTIONS(CERT_ID)

// Structure ASN.1 : RequesterCertificate ::= SEQUENCE { ... }
typedef struct requester_certificate_st {
    CERT_ID *certID;
    ASN1_OCTET_STRING *requestTime;
    ASN1_IA5STRING *locationInfo;
    ASN1_BIT_STRING *signature;
} REQUESTER_CERTIFICATE;

DECLARE_ASN1_FUNCTIONS(REQUESTER_CERTIFICATE)

// Function for verifying a relatedCertRequest attribute in a CSR
int verify_related_cert_request(X509_REQ *req);

int add_related_cert_request_to_csr(X509_REQ *req, EVP_PKEY *pkey, X509 *related_cert, const char *uri);


#ifdef __cplusplus
}
#endif

#endif 
