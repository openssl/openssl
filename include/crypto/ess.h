/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* internal ESS related stuff */

ESS_SIGNING_CERT *ESS_SIGNING_CERT_get(PKCS7_SIGNER_INFO *si);
int ESS_SIGNING_CERT_add(PKCS7_SIGNER_INFO *si, ESS_SIGNING_CERT *sc);

ESS_SIGNING_CERT *ESS_SIGNING_CERT_new_init(X509 *signcert,
                                            STACK_OF(X509) *certs,
                                            int issuer_needed);

ESS_SIGNING_CERT_V2 *ESS_SIGNING_CERT_V2_get(PKCS7_SIGNER_INFO *si);
int ESS_SIGNING_CERT_V2_add(PKCS7_SIGNER_INFO *si, ESS_SIGNING_CERT_V2 *sc);

ESS_SIGNING_CERT_V2 *ESS_SIGNING_CERT_V2_new_init(const EVP_MD *hash_alg,
                                                  X509 *signcert,
                                                  STACK_OF(X509) *certs,
                                                  int issuer_needed);

/* Returns < 0 if certificate is not found, certificate index otherwise. */
int ess_find_cert_v2(const STACK_OF(ESS_CERT_ID_V2) *cert_ids, const X509 *cert);
int ess_find_cert(const STACK_OF(ESS_CERT_ID) *cert_ids, X509 *cert);

/*-
 * IssuerSerial ::= SEQUENCE {
 *        issuer                  GeneralNames,
 *        serialNumber            CertificateSerialNumber
 * }
 */

struct ESS_issuer_serial {
    STACK_OF(GENERAL_NAME) *issuer;
    ASN1_INTEGER *serial;
};

/*-
 * ESSCertID ::=  SEQUENCE {
 *        certHash                Hash,
 *        issuerSerial            IssuerSerial OPTIONAL
 * }
 */

struct ESS_cert_id {
    ASN1_OCTET_STRING *hash;    /* Always SHA-1 digest. */
    ESS_ISSUER_SERIAL *issuer_serial;
};

/*-
 * SigningCertificate ::=  SEQUENCE {
 *        certs                   SEQUENCE OF ESSCertID,
 *        policies                SEQUENCE OF PolicyInformation OPTIONAL
 * }
 */

struct ESS_signing_cert {
    STACK_OF(ESS_CERT_ID) *cert_ids;
    STACK_OF(POLICYINFO) *policy_info;
};

/*-
 * ESSCertIDv2 ::=  SEQUENCE {
 *        hashAlgorithm           AlgorithmIdentifier DEFAULT id-sha256,
 *        certHash                Hash,
 *        issuerSerial            IssuerSerial OPTIONAL
 * }
 */

struct ESS_cert_id_v2_st {
    X509_ALGOR *hash_alg;       /* Default: SHA-256 */
    ASN1_OCTET_STRING *hash;
    ESS_ISSUER_SERIAL *issuer_serial;
};

/*-
 * SigningCertificateV2 ::= SEQUENCE {
 *        certs                   SEQUENCE OF ESSCertIDv2,
 *        policies                SEQUENCE OF PolicyInformation OPTIONAL
 * }
 */

struct ESS_signing_cert_v2_st {
    STACK_OF(ESS_CERT_ID_V2) *cert_ids;
    STACK_OF(POLICYINFO) *policy_info;
};
