/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OSSL_CRYPTO_X509_PMI_LOCAL_H)
#define OSSL_CRYPTO_X509_PMI_LOCAL_H

#include <openssl/asn1.h>
#include <openssl/bio.h>

/**
 * @brief Prints bytes as colon separated hexadecimal.
 * @param out the BIO to print to
 * @param buf the bytes to print
 * @param len the number of bytes at buf
 * @returns 1 on success, 0 on error
 */
int ossl_x509pmi_bio_print_hex(BIO *out, const unsigned char *buf, int len);

/**
 * @brief Prints an attribute value according to its ASN.1 type.
 * @param out the BIO to print to
 * @param obj_nid the NID of the attribute type, used to recognise values
 *                with DN syntax
 * @param av the attribute value
 * @param indent the number of spaces to indent by
 * @returns 1 on success, 0 on error
 */
int ossl_x509pmi_print_attribute_value(BIO *out, int obj_nid,
    const ASN1_TYPE *av, int indent);

#endif /* !defined(OSSL_CRYPTO_X509_PMI_LOCAL_H) */
