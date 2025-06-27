#ifndef V3_CERTBIND_H
#define V3_CERTBIND_H

#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/evp.h>
#include <openssl/stack.h>

#ifdef __cplusplus
extern "C" {
#endif

// Structure ASN.1 : CertID ::= SEQUENCE { issuer Name, serialNumber INTEGER }
typedef struct cert_id_st {
    X509_NAME *issuer;
    ASN1_INTEGER *serialNumber;
} CERT_ID;

DECLARE_ASN1_FUNCTIONS(CERT_ID)

// Structure ASN.1 : BinaryTime according to RFC 6019
typedef struct binary_time_st {
    ASN1_OCTET_STRING *time;
} BINARY_TIME;

DECLARE_ASN1_FUNCTIONS(BINARY_TIME)

// Structure ASN.1 : UniformResourceIdentifiers ::= SEQUENCE SIZE (1..MAX) OF URI
typedef struct uniform_resource_identifiers_st {
    STACK_OF(ASN1_IA5STRING) *uris;
} UNIFORM_RESOURCE_IDENTIFIERS;

DECLARE_ASN1_FUNCTIONS(UNIFORM_RESOURCE_IDENTIFIERS)

// Structure ASN.1 : RequesterCertificate ::= SEQUENCE { 
//   certID CertID, 
//   requestTime BinaryTime, 
//   locationInfo UniformResourceIdentifiers, 
//   signature BIT STRING OPTIONAL 
// }
typedef struct requester_certificate_st {
    CERT_ID *certID;
    BINARY_TIME *requestTime;
    UNIFORM_RESOURCE_IDENTIFIERS *locationInfo;
    ASN1_BIT_STRING *signature;
} REQUESTER_CERTIFICATE;

DECLARE_ASN1_FUNCTIONS(REQUESTER_CERTIFICATE)

// Structure ASN.1 : RelatedCertificate ::= SEQUENCE { hashAlgorithm, hashValue }
typedef struct related_certificate_st {
    X509_ALGOR *hashAlgorithm;
    ASN1_OCTET_STRING *hashValue;
} RELATED_CERTIFICATE;

DECLARE_ASN1_FUNCTIONS(RELATED_CERTIFICATE)

// Function for verifying a relatedCertRequest attribute in a CSR
int verify_related_cert_request(X509_REQ *req);

// Function for adding relatedCertRequest attribute to a CSR
int add_related_cert_request_to_csr(X509_REQ *req, EVP_PKEY *pkey, X509 *related_cert, 
                                   const char *uri, const EVP_MD *hash_alg);

// Function for adding RelatedCertificate extension to X.509 certificate
int add_related_certificate_extension(X509 *cert, X509 *related_cert, const EVP_MD *hash_alg);

// Function for verifying RelatedCertificate extension
int verify_related_certificate_extension(X509 *cert, X509 *related_cert);

// Function for extracting RelatedCertificate extension from certificate
RELATED_CERTIFICATE *get_related_certificate_extension(X509 *cert);

// Function for printing RelatedCertificate extension
int print_related_certificate_extension(BIO *bio, X509 *cert, int indent);

// Function for printing relatedCertRequest attribute from CSR
int print_related_cert_request(BIO *bio, X509_REQ *req, int indent);

#ifdef __cplusplus
}
#endif

#endif 
