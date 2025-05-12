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
    ASN1_OBJECT *obj = NULL;
    X509_ATTRIBUTE *attr = NULL;
    unsigned char *buf = NULL, *sigbuf = NULL;
    int len = 0;
    size_t siglen = 0;
    EVP_MD_CTX *mdctx = NULL;

    // Build REQUESTER_CERTIFICATE
    rcr = REQUESTER_CERTIFICATE_new();
    if (!rcr) goto err;

    cid = CERT_ID_new();
    if (!cid) goto err;
    cid->issuer = X509_NAME_dup(X509_get_issuer_name(related_cert));
    cid->serialNumber = ASN1_INTEGER_dup(X509_get_serialNumber(related_cert));
    rcr->certID = cid;

    time_t now = time(NULL);
    char timestr[20];
    BIO_snprintf(timestr, sizeof(timestr), "%ld", now);
    rcr->requestTime = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(rcr->requestTime, (const unsigned char *)timestr, strlen(timestr));

    rcr->locationInfo = ASN1_IA5STRING_new();
    ASN1_STRING_set(rcr->locationInfo, uri, strlen(uri));

    // Remove signature temporarily for signing
    rcr->signature = NULL;
    len = i2d_REQUESTER_CERTIFICATE(rcr, NULL);
    if (len <= 0) goto err;

    buf = OPENSSL_malloc(len);
    if (!buf) goto err;
    unsigned char *p = buf;
    if (i2d_REQUESTER_CERTIFICATE(rcr, &p) <= 0) goto err;
    
   
    // Sign the encoded structure
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) goto err;

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0 ||
        EVP_DigestSignUpdate(mdctx, buf, len) <= 0 ||
        EVP_DigestSignFinal(mdctx, NULL, &siglen) <= 0) goto err;

    sigbuf = OPENSSL_malloc(siglen);
    if (!sigbuf) goto err;

    if (EVP_DigestSignFinal(mdctx, sigbuf, &siglen) <= 0) goto err;

    EVP_MD_CTX_free(mdctx); mdctx = NULL;
    OPENSSL_free(buf); buf = NULL;

    rcr->signature = ASN1_BIT_STRING_new();
    if (!rcr->signature || !ASN1_BIT_STRING_set(rcr->signature, sigbuf, siglen)) goto err;
    rcr->signature->flags &= ~ASN1_STRING_FLAG_BITS_LEFT;

    // Re-encode with signature
    len = i2d_REQUESTER_CERTIFICATE(rcr, NULL);
    if (len <= 0) goto err;
    buf = OPENSSL_malloc(len);
    if (!buf) goto err;
    p = buf;
    if (i2d_REQUESTER_CERTIFICATE(rcr, &p) <= 0) goto err;

    obj = OBJ_txt2obj("1.3.6.1.4.1.99999.1.1", 1);
    attr = X509_ATTRIBUTE_create_by_OBJ(NULL, obj, V_ASN1_SEQUENCE, buf, len);
    if (!attr || !X509_REQ_add1_attr(req, attr)) goto err;

    ret = 1;

err:
    if (!ret) fprintf(stderr, "Error adding relatedCertRequest to CSR\n");
    REQUESTER_CERTIFICATE_free(rcr);
    X509_ATTRIBUTE_free(attr);
    ASN1_OBJECT_free(obj);
    OPENSSL_clear_free(buf, len);
    OPENSSL_clear_free(sigbuf, siglen);
    EVP_MD_CTX_free(mdctx);
    return ret;
}



//Minimal PEM certificate loader
static X509 *load_cert_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp)
        return NULL;
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    return cert;
}

int verify_related_cert_request(X509_REQ *req) {
    BIO *out = BIO_new_fp(stderr, BIO_NOCLOSE);

    int idx = X509_REQ_get_attr_by_NID(req, OBJ_txt2nid("1.3.6.1.4.1.99999.1.1"), -1);
    if (idx < 0) {
        BIO_printf(out, "relatedCertRequest attribute not found\n");
        BIO_free(out);
        return 0;
    }

    X509_ATTRIBUTE *attr = X509_REQ_get_attr(req, idx);
    const ASN1_TYPE *av = X509_ATTRIBUTE_get0_type(attr, 0);
    if (!av || av->type != V_ASN1_SEQUENCE) {
        BIO_printf(out, "Invalid relatedCertRequest format\n");
        BIO_free(out);
        return 0;
    }

    const unsigned char *p = av->value.sequence->data;
    REQUESTER_CERTIFICATE *rcr = d2i_REQUESTER_CERTIFICATE(NULL, &p, av->value.sequence->length);
    if (!rcr) {
        BIO_printf(out, "Unable to decode relatedCertRequest attribute\n");
        BIO_free(out);
        return 0;
    }

    // Extract path
    char uri[512] = {0};
    memcpy(uri, rcr->locationInfo->data, rcr->locationInfo->length < sizeof(uri)-1 ? rcr->locationInfo->length : sizeof(uri)-1);
    X509 *related_cert = load_cert_file(uri);
    if (!related_cert) {
        BIO_printf(out, "Unable to load related certificate from: %s\n", uri);
        REQUESTER_CERTIFICATE_free(rcr);
        BIO_free(out);
        return 0;
    }

    if (X509_NAME_cmp(rcr->certID->issuer, X509_get_issuer_name(related_cert)) != 0 ||
        ASN1_INTEGER_cmp(rcr->certID->serialNumber, X509_get_serialNumber(related_cert)) != 0) {
        BIO_printf(out, "certID does not match related certificate\n");
        X509_free(related_cert);
        REQUESTER_CERTIFICATE_free(rcr);
        BIO_free(out);
        return 0;
    }

    // Check timestamp freshness
    char timestr[32] = {0};
    memcpy(timestr, rcr->requestTime->data, rcr->requestTime->length < sizeof(timestr) ? rcr->requestTime->length : sizeof(timestr)-1);
    time_t t_req = atol(timestr), now = time(NULL);
    if (labs(now - t_req) > 300) {
        BIO_printf(out, "requestTime not fresh (delta: %ld seconds)\n", labs(now - t_req));
        X509_free(related_cert);
        REQUESTER_CERTIFICATE_free(rcr);
        BIO_free(out);
        return 0;
    }

    // Signature verification
    ASN1_BIT_STRING *saved_sig = rcr->signature;
    rcr->signature = NULL;

    int len = i2d_REQUESTER_CERTIFICATE(rcr, NULL);
    unsigned char *encoded = OPENSSL_malloc(len);
    unsigned char *tmp = encoded;
    i2d_REQUESTER_CERTIFICATE(rcr, &tmp);
    
    rcr->signature = saved_sig;

    EVP_PKEY *pubkey = X509_get_pubkey(related_cert);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = 0;

    if (ctx &&
        EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey) == 1 &&
        EVP_DigestVerifyUpdate(ctx, encoded, len) == 1 &&
        EVP_DigestVerifyFinal(ctx, rcr->signature->data, rcr->signature->length) == 1) {
        BIO_printf(out, "relatedCertRequest signature verification OK\n");
        ok = 1;
    } else {
        BIO_printf(out, "relatedCertRequest signature verification FAILED\n");
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
    OPENSSL_free(encoded);
    X509_free(related_cert);
    REQUESTER_CERTIFICATE_free(rcr);
    BIO_free(out);
    return ok;
}
