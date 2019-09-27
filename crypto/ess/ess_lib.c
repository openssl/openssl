/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/ess.h>
#include "crypto/ess.h"

static ESS_CERT_ID *ESS_CERT_ID_new_init(X509 *cert, int issuer_needed);
static ESS_CERT_ID_V2 *ESS_CERT_ID_V2_new_init(const EVP_MD *hash_alg,
                                               X509 *cert, int issuer_needed);

ESS_SIGNING_CERT *ESS_SIGNING_CERT_new_init(X509 *signcert,
                                            STACK_OF(X509) *certs,
                                            int issuer_needed)
{
    ESS_CERT_ID *cid = NULL;
    ESS_SIGNING_CERT *sc;
    int i;

    if ((sc = ESS_SIGNING_CERT_new()) == NULL)
        goto err;
    if (sc->cert_ids == NULL
        && (sc->cert_ids = sk_ESS_CERT_ID_new_null()) == NULL)
        goto err;

    if ((cid = ESS_CERT_ID_new_init(signcert, issuer_needed)) == NULL
        || !sk_ESS_CERT_ID_push(sc->cert_ids, cid))
        goto err;
    for (i = 0; i < sk_X509_num(certs); ++i) {
        X509 *cert = sk_X509_value(certs, i);
        if ((cid = ESS_CERT_ID_new_init(cert, 1)) == NULL
            || !sk_ESS_CERT_ID_push(sc->cert_ids, cid))
            goto err;
    }

    return sc;
 err:
    ESS_SIGNING_CERT_free(sc);
    ESS_CERT_ID_free(cid);
    ESSerr(ESS_F_ESS_SIGNING_CERT_NEW_INIT, ERR_R_MALLOC_FAILURE);
    return NULL;
}

static ESS_CERT_ID *ESS_CERT_ID_new_init(X509 *cert, int issuer_needed)
{
    ESS_CERT_ID *cid = NULL;
    GENERAL_NAME *name = NULL;
    unsigned char cert_sha1[SHA_DIGEST_LENGTH];

    /* Call for side-effect of computing hash and caching extensions */
    X509_check_purpose(cert, -1, 0);
    if ((cid = ESS_CERT_ID_new()) == NULL)
        goto err;
    X509_digest(cert, EVP_sha1(), cert_sha1, NULL);
    if (!ASN1_OCTET_STRING_set(cid->hash, cert_sha1, SHA_DIGEST_LENGTH))
        goto err;

    /* Setting the issuer/serial if requested. */
    if (!issuer_needed)
        return cid;

    if (cid->issuer_serial == NULL
        && (cid->issuer_serial = ESS_ISSUER_SERIAL_new()) == NULL)
        goto err;
    if ((name = GENERAL_NAME_new()) == NULL)
        goto err;
    name->type = GEN_DIRNAME;
    if ((name->d.dirn = X509_NAME_dup(X509_get_issuer_name(cert))) == NULL)
        goto err;
    if (!sk_GENERAL_NAME_push(cid->issuer_serial->issuer, name))
        goto err;
    name = NULL;            /* Ownership is lost. */
    ASN1_INTEGER_free(cid->issuer_serial->serial);
    if (!(cid->issuer_serial->serial =
          ASN1_INTEGER_dup(X509_get_serialNumber(cert))))
        goto err;

    return cid;
 err:
    GENERAL_NAME_free(name);
    ESS_CERT_ID_free(cid);
    ESSerr(ESS_F_ESS_CERT_ID_NEW_INIT, ERR_R_MALLOC_FAILURE);
    return NULL;
}

ESS_SIGNING_CERT_V2 *ESS_SIGNING_CERT_V2_new_init(const EVP_MD *hash_alg,
                                                  X509 *signcert,
                                                  STACK_OF(X509) *certs,
                                                  int issuer_needed)
{
    ESS_CERT_ID_V2 *cid = NULL;
    ESS_SIGNING_CERT_V2 *sc;
    int i;

    if ((sc = ESS_SIGNING_CERT_V2_new()) == NULL)
        goto err;
    if ((cid = ESS_CERT_ID_V2_new_init(hash_alg, signcert, issuer_needed)) == NULL)
        goto err;
    if (!sk_ESS_CERT_ID_V2_push(sc->cert_ids, cid))
        goto err;
    cid = NULL;

    for (i = 0; i < sk_X509_num(certs); ++i) {
        X509 *cert = sk_X509_value(certs, i);

        if ((cid = ESS_CERT_ID_V2_new_init(hash_alg, cert, 1)) == NULL)
            goto err;
        if (!sk_ESS_CERT_ID_V2_push(sc->cert_ids, cid))
            goto err;
        cid = NULL;
    }

    return sc;
 err:
    ESS_SIGNING_CERT_V2_free(sc);
    ESS_CERT_ID_V2_free(cid);
    ESSerr(ESS_F_ESS_SIGNING_CERT_V2_NEW_INIT, ERR_R_MALLOC_FAILURE);
    return NULL;
}

static ESS_CERT_ID_V2 *ESS_CERT_ID_V2_new_init(const EVP_MD *hash_alg,
                                               X509 *cert, int issuer_needed)
{
    ESS_CERT_ID_V2 *cid;
    GENERAL_NAME *name = NULL;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = sizeof(hash);
    X509_ALGOR *alg = NULL;

    memset(hash, 0, sizeof(hash));

    if ((cid = ESS_CERT_ID_V2_new()) == NULL)
        goto err;

    if (hash_alg != EVP_sha256()) {
        alg = X509_ALGOR_new();
        if (alg == NULL)
            goto err;
        X509_ALGOR_set_md(alg, hash_alg);
        if (alg->algorithm == NULL)
            goto err;
        cid->hash_alg = alg;
        alg = NULL;
    } else {
        cid->hash_alg = NULL;
    }

    if (!X509_digest(cert, hash_alg, hash, &hash_len))
        goto err;

    if (!ASN1_OCTET_STRING_set(cid->hash, hash, hash_len))
        goto err;

    if (!issuer_needed)
        return cid;

    if ((cid->issuer_serial = ESS_ISSUER_SERIAL_new()) == NULL)
        goto err;
    if ((name = GENERAL_NAME_new()) == NULL)
        goto err;
    name->type = GEN_DIRNAME;
    if ((name->d.dirn = X509_NAME_dup(X509_get_issuer_name(cert))) == NULL)
        goto err;
    if (!sk_GENERAL_NAME_push(cid->issuer_serial->issuer, name))
        goto err;
    name = NULL;            /* Ownership is lost. */
    ASN1_INTEGER_free(cid->issuer_serial->serial);
    cid->issuer_serial->serial = ASN1_INTEGER_dup(X509_get_serialNumber(cert));
    if (cid->issuer_serial->serial == NULL)
        goto err;

    return cid;
 err:
    X509_ALGOR_free(alg);
    GENERAL_NAME_free(name);
    ESS_CERT_ID_V2_free(cid);
    ESSerr(ESS_F_ESS_CERT_ID_V2_NEW_INIT, ERR_R_MALLOC_FAILURE);
    return NULL;
}

ESS_SIGNING_CERT *ESS_SIGNING_CERT_get(PKCS7_SIGNER_INFO *si)
{
    ASN1_TYPE *attr;
    const unsigned char *p;
    attr = PKCS7_get_signed_attribute(si, NID_id_smime_aa_signingCertificate);
    if (!attr)
        return NULL;
    p = attr->value.sequence->data;
    return d2i_ESS_SIGNING_CERT(NULL, &p, attr->value.sequence->length);
}

ESS_SIGNING_CERT_V2 *ESS_SIGNING_CERT_V2_get(PKCS7_SIGNER_INFO *si)
{
    ASN1_TYPE *attr;
    const unsigned char *p;

    attr = PKCS7_get_signed_attribute(si, NID_id_smime_aa_signingCertificateV2);
    if (attr == NULL)
        return NULL;
    p = attr->value.sequence->data;
    return d2i_ESS_SIGNING_CERT_V2(NULL, &p, attr->value.sequence->length);
}

int ESS_SIGNING_CERT_add(PKCS7_SIGNER_INFO *si, ESS_SIGNING_CERT *sc)
{
    ASN1_STRING *seq = NULL;
    unsigned char *p, *pp = NULL;
    int len;

    len = i2d_ESS_SIGNING_CERT(sc, NULL);
    if ((pp = OPENSSL_malloc(len)) == NULL) {
        ESSerr(ESS_F_ESS_SIGNING_CERT_ADD, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    p = pp;
    i2d_ESS_SIGNING_CERT(sc, &p);
    if ((seq = ASN1_STRING_new()) == NULL || !ASN1_STRING_set(seq, pp, len)) {
        ESSerr(ESS_F_ESS_SIGNING_CERT_ADD, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    OPENSSL_free(pp);
    pp = NULL;
    return PKCS7_add_signed_attribute(si,
                                      NID_id_smime_aa_signingCertificate,
                                      V_ASN1_SEQUENCE, seq);
 err:
    ASN1_STRING_free(seq);
    OPENSSL_free(pp);

    return 0;
}

int ESS_SIGNING_CERT_V2_add(PKCS7_SIGNER_INFO *si,
                            ESS_SIGNING_CERT_V2 *sc)
{
    ASN1_STRING *seq = NULL;
    unsigned char *p, *pp = NULL;
    int len = i2d_ESS_SIGNING_CERT_V2(sc, NULL);

    if ((pp = OPENSSL_malloc(len)) == NULL) {
        ESSerr(ESS_F_ESS_SIGNING_CERT_V2_ADD, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    p = pp;
    i2d_ESS_SIGNING_CERT_V2(sc, &p);
    if ((seq = ASN1_STRING_new()) == NULL || !ASN1_STRING_set(seq, pp, len)) {
        ESSerr(ESS_F_ESS_SIGNING_CERT_V2_ADD, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    OPENSSL_free(pp);
    pp = NULL;
    return PKCS7_add_signed_attribute(si,
                                      NID_id_smime_aa_signingCertificateV2,
                                      V_ASN1_SEQUENCE, seq);
 err:
    ASN1_STRING_free(seq);
    OPENSSL_free(pp);
    return 0;
}
