/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Build trusted Merkle Tree Certificate CAs from the certificates that
 * represent them (section 5.5 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/).
 * The experimental OIDs are used: the CA ID is a RELATIVE-OID subject
 * attribute (1.3.6.1.4.1.44363.47.3) and the parameters are carried in the
 * id-pe-mtcCertificationAuthority-SHA256 extension (1.3.6.1.4.1.44363.47.4).
 * The PEM reader is shared with the cosigner certificate parser
 * (mtc_cosigner.c), which reads the same subject attribute from a certificate
 * without the extension.
 */

#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mtc.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "crypto/mtc_ca.h"
#include "crypto/mtc_verify.h"

/* mtcMinSerial, the smallest serial number an MTC CA may issue (5.5). */
#define MTC_MIN_SERIAL (UINT64_C(1) << 48)

typedef struct {
    X509_ALGOR *sigAlg;
    ASN1_INTEGER *minSerial;
    ASN1_INTEGER *maxSerial;
} MTC_CERTIFICATION_AUTHORITY;

DECLARE_ASN1_ITEM(MTC_CERTIFICATION_AUTHORITY)

ASN1_SEQUENCE(MTC_CERTIFICATION_AUTHORITY) = {
    ASN1_SIMPLE(MTC_CERTIFICATION_AUTHORITY, sigAlg, X509_ALGOR),
    ASN1_SIMPLE(MTC_CERTIFICATION_AUTHORITY, minSerial, ASN1_INTEGER),
    ASN1_SIMPLE(MTC_CERTIFICATION_AUTHORITY, maxSerial, ASN1_INTEGER),
} ASN1_SEQUENCE_END(MTC_CERTIFICATION_AUTHORITY)

/*
 * The index of the id-pe-mtcCertificationAuthority-SHA256 extension in cert,
 * or -1 if absent.
 */
static int ca_ext_index(const X509 *cert)
{
    ASN1_OBJECT *ext_oid = OBJ_txt2obj("1.3.6.1.4.1.44363.47.4", 1);
    int idx;

    if (ext_oid == NULL)
        return -1;
    idx = X509_get_ext_by_OBJ(cert, ext_oid, -1);
    ASN1_OBJECT_free(ext_oid);
    if (idx < 0)
        idx = X509_get_ext_by_NID(cert,
            NID_id_pe_mtcCertificationAuthority_SHA256, -1);
    return idx;
}

int ossl_mtc_cert_is_ca(const X509 *cert)
{
    return ca_ext_index(cert) >= 0;
}

/*
 * Decode the id-pe-mtcCertificationAuthority-SHA256 extension, or NULL if
 * absent, not marked critical (section 5.5), or not exactly one
 * MTCCertificationAuthority.
 */
static MTC_CERTIFICATION_AUTHORITY *ca_params_from_cert(X509 *cert)
{
    MTC_CERTIFICATION_AUTHORITY *params = NULL;
    const ASN1_OCTET_STRING *data;
    const unsigned char *p;
    const X509_EXTENSION *ext;
    long len;
    int idx = ca_ext_index(cert);

    if (idx < 0)
        return NULL;
    ext = X509_get_ext(cert, idx);
    if (!X509_EXTENSION_get_critical(ext))
        return NULL;
    data = X509_EXTENSION_get_data(ext);
    p = ASN1_STRING_get0_data(data);
    len = (long)ASN1_STRING_get_length(data);
    params = (MTC_CERTIFICATION_AUTHORITY *)ASN1_item_d2i(NULL, &p, len,
        ASN1_ITEM_rptr(MTC_CERTIFICATION_AUTHORITY));
    if (params != NULL && p != ASN1_STRING_get0_data(data) + len) {
        ASN1_item_free((ASN1_VALUE *)params,
            ASN1_ITEM_rptr(MTC_CERTIFICATION_AUTHORITY));
        return NULL; /* trailing bytes after the value */
    }
    return params;
}

/* Build one trusted CA from a certificate that represents it. */
static OSSL_MTC_CA *ca_from_cert(OSSL_LIB_CTX *libctx, const char *propq,
    X509 *cert)
{
    MTC_CERTIFICATION_AUTHORITY *params = NULL;
    uint8_t *ca_id = NULL;
    size_t ca_id_len = 0;
    OSSL_MTC_CA *ca = NULL;
    EVP_PKEY *cosigner;
    EVP_MD *hash = NULL;
    uint64_t min_serial, max_serial;

    if (!ossl_mtc_ca_id_from_name(X509_get_subject_name(cert), &ca_id,
            &ca_id_len)
        || (params = ca_params_from_cert(cert)) == NULL
        || (cosigner = X509_get0_pubkey(cert)) == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    /*
     * sigAlg is checked for recognition but not otherwise used: the cosigner's
     * public key specifies its own signature algorithm (section 5.3.3).
     */
    if (OBJ_obj2nid(params->sigAlg->algorithm) == NID_undef
        || !ASN1_INTEGER_get_uint64(&min_serial, params->minSerial)
        || !ASN1_INTEGER_get_uint64(&max_serial, params->maxSerial)
        || min_serial < MTC_MIN_SERIAL || max_serial < min_serial) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    /* The extension's OID fixes the log hash to SHA-256 (section 5.5). */
    if ((hash = EVP_MD_fetch(libctx, "SHA2-256", propq)) == NULL)
        goto err;
    ca = OSSL_MTC_CA_new(ca_id, ca_id_len, hash, min_serial, cosigner);
    if (ca != NULL && !OSSL_MTC_CA_set_max_serial(ca, max_serial)) {
        OSSL_MTC_CA_free(ca);
        ca = NULL;
    }

err:
    EVP_MD_free(hash);
    ASN1_item_free((ASN1_VALUE *)params,
        ASN1_ITEM_rptr(MTC_CERTIFICATION_AUTHORITY));
    OPENSSL_free(ca_id);
    return ca;
}

int ossl_mtc_parse_pem_certificates(OSSL_LIB_CTX *libctx, const char *propq,
    BIO *in, int (*cb)(OSSL_LIB_CTX *libctx, const char *propq, X509 *cert, void *arg),
    void *arg)
{
    int block = 0;

    for (;;) {
        char *name = NULL, *header = NULL;
        unsigned char *data = NULL;
        long len = 0;
        int ok = 1;

        if (!PEM_read_bio(in, &name, &header, &data, &len)) {
            /* A missing start line at this point simply means end of input. */
            if (ERR_GET_REASON(ERR_peek_last_error()) == PEM_R_NO_START_LINE) {
                ERR_clear_error();
                return 1;
            }
            return 0;
        }
        block++;

        if (strcmp(name, "CERTIFICATE") == 0) {
            const unsigned char *p = data;
            X509 *cert = X509_new_ex(libctx, propq);

            ok = cert != NULL && d2i_X509(&cert, &p, len) != NULL
                && cb(libctx, propq, cert, arg);
            X509_free(cert);
        } else {
            ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT,
                "PEM block %d", block);
            ok = 0;
        }

        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
        if (!ok)
            return 0;
    }
}

/* Build a CA from one certificate and push it onto the stack in arg. */
static int push_ca(OSSL_LIB_CTX *libctx, const char *propq, X509 *cert,
    void *arg)
{
    STACK_OF(OSSL_MTC_CA) *out_cas = arg;
    OSSL_MTC_CA *ca = ca_from_cert(libctx, propq, cert);

    if (ca == NULL || sk_OSSL_MTC_CA_push(out_cas, ca) <= 0) {
        OSSL_MTC_CA_free(ca);
        return 0;
    }
    return 1;
}

int OSSL_MTC_CA_parse_certificates(OSSL_LIB_CTX *libctx, const char *propq,
    BIO *in, STACK_OF(OSSL_MTC_CA) *out_cas)
{
    int start;

    if (in == NULL || out_cas == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /* Remember the starting size so a failure leaves out_cas unchanged. */
    start = sk_OSSL_MTC_CA_num(out_cas);
    if (ossl_mtc_parse_pem_certificates(libctx, propq, in, push_ca, out_cas))
        return 1;
    while (sk_OSSL_MTC_CA_num(out_cas) > start)
        OSSL_MTC_CA_free(sk_OSSL_MTC_CA_pop(out_cas));
    return 0;
}
