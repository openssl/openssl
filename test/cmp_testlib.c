/*
 * Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "cmp_testlib.h"
#include <openssl/rsa.h> /* needed in case config no-deprecated */

EVP_PKEY *load_pem_key(const char *file)
{
    EVP_PKEY *key = NULL;
    BIO *bio = NULL;

    if (!TEST_ptr(bio = BIO_new(BIO_s_file())))
        return NULL;
    if (TEST_int_gt(BIO_read_filename(bio, file), 0))
        (void)TEST_ptr(key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL));

    BIO_free(bio);
    return key;
}

X509 *load_pem_cert(const char *file)
{
    X509 *cert = NULL;
    BIO *bio = NULL;

    if (!TEST_ptr(bio = BIO_new(BIO_s_file())))
        return NULL;
    if (TEST_int_gt(BIO_read_filename(bio, file), 0))
        (void)TEST_ptr(cert = PEM_read_bio_X509(bio, NULL, NULL, NULL));

    BIO_free(bio);
    return cert;
}

X509_REQ *load_csr(const char *file)
{
    X509_REQ *csr = NULL;
    BIO *bio = NULL;

    if (!TEST_ptr(file) || !TEST_ptr(bio = BIO_new_file(file, "rb")))
        return NULL;
    (void)TEST_ptr(csr = d2i_X509_REQ_bio(bio, NULL));
    BIO_free(bio);
    return csr;
}

EVP_PKEY *gen_rsa(void)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    (void)(TEST_ptr(ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL))
               && TEST_int_gt(EVP_PKEY_keygen_init(ctx), 0)
               && TEST_int_gt(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048), 0)
               && TEST_int_gt(EVP_PKEY_keygen(ctx, &pkey), 0));
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/*
 * Checks whether the syntax of msg conforms to ASN.1
 */
int valid_asn1_encoding(const OSSL_CMP_MSG *msg)
{
    return msg != NULL ? i2d_OSSL_CMP_MSG(msg, NULL) > 0 : 0;
}

/*
 * Compares two stacks of certificates in the order of their elements.
 * Returns 0 if sk1 and sk2 are equal and another value otherwise
 */
int STACK_OF_X509_cmp(const STACK_OF(X509) *sk1, const STACK_OF(X509) *sk2)
{
    int i, res;
    X509 *a, *b;

    if (sk1 == sk2)
        return 0;
    if (sk1 == NULL)
        return -1;
    if (sk2 == NULL)
        return 1;
    if ((res = sk_X509_num(sk1) - sk_X509_num(sk2)))
        return res;
    for (i = 0; i < sk_X509_num(sk1); i++) {
        a = sk_X509_value(sk1, i);
        b = sk_X509_value(sk2, i);
        if (a != b)
            if ((res = X509_cmp(a, b)) != 0)
                return res;
    }
    return 0;
}

/*
 * Up refs and push a cert onto sk.
 * Returns the number of certificates on the stack on success
 * Returns -1 or 0 on error
 */
int STACK_OF_X509_push1(STACK_OF(X509) *sk, X509 *cert)
{
    int res;

    if (sk == NULL || cert == NULL)
        return -1;
    if (!X509_up_ref(cert))
        return -1;
    res = sk_X509_push(sk, cert);
    if (res <= 0)
        X509_free(cert); /* down-ref */
    return res;
}
