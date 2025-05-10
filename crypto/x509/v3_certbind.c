/* certbind.c - Implements the relatedCertRequest attribute for CSRs and relatedCertificate extension */

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1t.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <openssl/obj_mac.h>
#include <openssl/v3_certbind.h>

//definition of ASN.1 structures
ASN1_SEQUENCE(CERT_ID) = {
    ASN1_SIMPLE(CERT_ID, issuer, X509_NAME),
    ASN1_SIMPLE(CERT_ID, serialNumber, ASN1_INTEGER)
} ASN1_SEQUENCE_END(CERT_ID)
IMPLEMENT_ASN1_FUNCTIONS(CERT_ID)

ASN1_SEQUENCE(REQUESTER_CERTIFICATE) = {
    ASN1_SIMPLE(REQUESTER_CERTIFICATE, certID, CERT_ID),
    ASN1_SIMPLE(REQUESTER_CERTIFICATE, requestTime, ASN1_OCTET_STRING),
    ASN1_SIMPLE(REQUESTER_CERTIFICATE, locationInfo, ASN1_IA5STRING),
    ASN1_OPT(REQUESTER_CERTIFICATE, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(REQUESTER_CERTIFICATE)
IMPLEMENT_ASN1_FUNCTIONS(REQUESTER_CERTIFICATE)


int add_related_cert_request_to_csr(X509_REQ *req, EVP_PKEY *pkey, X509 *related_cert, const char *uri) {
    if (!req || !pkey || !related_cert || !uri)
        return 0;

    int ret = 0;
    REQUESTER_CERTIFICATE *rcr = NULL;
    CERT_ID *cid = NULL;
    ASN1_TYPE *attrib_value = NULL;
    ASN1_OBJECT *obj = NULL;
    unsigned char *buf = NULL;
    int len;

    // Allocate structures
    rcr = REQUESTER_CERTIFICATE_new();
    if (!rcr)
        goto err;

    // Fill CERT_ID
    cid = CERT_ID_new();
    if (!cid)
        goto err;
    cid->issuer = X509_NAME_dup(X509_get_issuer_name(related_cert));
    cid->serialNumber = ASN1_INTEGER_dup(X509_get_serialNumber(related_cert));
    rcr->certID = cid;

    // Current time as ASN1_OCTET_STRING
    time_t now = time(NULL);
    char timestr[20];
    BIO_snprintf(timestr, sizeof(timestr), "%ld", now);
    rcr->requestTime = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(rcr->requestTime, (unsigned char *)timestr, strlen(timestr));

    // URI as IA5String
    rcr->locationInfo = ASN1_IA5STRING_new();
    ASN1_STRING_set(rcr->locationInfo, uri, strlen(uri));

    // First encode without a signature to calculate it
    rcr->signature = NULL;
    len = i2d_REQUESTER_CERTIFICATE(rcr, NULL);
    if (len <= 0)
        goto err;

    buf = OPENSSL_malloc(len);
    if (!buf)
        goto err;

    unsigned char *p = buf;
    if (i2d_REQUESTER_CERTIFICATE(rcr, &p) <= 0) {
        fprintf(stderr, "Failed to encode structure for signing\n");
        goto err;
    }

    // Sign the DER-encoded structure
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        goto err;

    const EVP_MD *md = EVP_sha256();
    unsigned char sigbuf[512];
    size_t siglen;

    if (!EVP_SignInit(mdctx, md) ||
        !EVP_SignUpdate(mdctx, buf, len) ||
        !EVP_SignFinal(mdctx, sigbuf, (unsigned int *)&siglen, pkey)) {
        EVP_MD_CTX_free(mdctx);
        goto err;
    }
    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(buf);

    // Add signature to structure
    rcr->signature = ASN1_BIT_STRING_new();
    ASN1_STRING_set(rcr->signature, sigbuf, siglen);
    rcr->signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT);

    // Re-encode with signature
    len = i2d_REQUESTER_CERTIFICATE(rcr, NULL);
    buf = OPENSSL_malloc(len);
    if (!buf)
        goto err;

    p = buf;
    if (i2d_REQUESTER_CERTIFICATE(rcr, &p) <= 0)
        goto err;

    // Create X509_ATTRIBUTE and add it to the request
    obj = OBJ_nid2obj(NID_id_aa_relatedCertRequest);
    if (!obj)
        goto err;

    attrib_value = ASN1_TYPE_new();
    if (!attrib_value)
        goto err;

    ASN1_TYPE_set(attrib_value, V_ASN1_SEQUENCE, ASN1_STRING_type_new(V_ASN1_SEQUENCE));
    ASN1_STRING_set(attrib_value->value.sequence, buf, len);

    X509_ATTRIBUTE *attr = X509_ATTRIBUTE_new();
    X509_ATTRIBUTE_set1_object(attr, obj);
    X509_ATTRIBUTE_set1_data(attr, V_ASN1_SEQUENCE, buf, len);
    X509_REQ_add1_attr(req, attr);

    ret = 1;

err:
    if (!ret)
        fprintf(stderr, "Error adding relatedCertRequest to CSR\n");
    REQUESTER_CERTIFICATE_free(rcr);
    ASN1_TYPE_free(attrib_value);
    ASN1_OBJECT_free(obj);
    if (buf)
        OPENSSL_free(buf);
    return ret;
}
