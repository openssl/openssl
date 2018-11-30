/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* ESS related stuff */

/*-
 * IssuerSerial ::= SEQUENCE {
 *         issuer                   GeneralNames,
 *         serialNumber             CertificateSerialNumber
 *         }
 */

struct ESS_issuer_serial {
    STACK_OF(GENERAL_NAME) *issuer;
    ASN1_INTEGER *serial;
};

/*-
 * ESSCertID ::=  SEQUENCE {
 *         certHash                 Hash,
 *         issuerSerial             IssuerSerial OPTIONAL
 * }
 */

struct ESS_cert_id {
    ASN1_OCTET_STRING *hash;    /* Always SHA-1 digest. */
    ESS_ISSUER_SERIAL *issuer_serial;
};

/*-
 * SigningCertificate ::=  SEQUENCE {
 *        certs        SEQUENCE OF ESSCertID,
 *        policies     SEQUENCE OF PolicyInformation OPTIONAL
 * }
 */

struct ESS_signing_cert {
    STACK_OF(ESS_CERT_ID) *cert_ids;
    STACK_OF(POLICYINFO) *policy_info;
};

/*-
 * ESSCertIDv2 ::=  SEQUENCE {
 *        hashAlgorithm           AlgorithmIdentifier
 *                DEFAULT {algorithm id-sha256},
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
