/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>         /* For public PEM and PVK functions */
#include <openssl/pkcs12.h>
#include "internal/pem.h"        /* For internal PVK and "blob" functions */
#include "internal/cryptlib.h"
#include "internal/asn1.h"
#include "internal/passphrase.h"
#include "prov/bio.h"               /* ossl_prov_bio_printf() */
#include "prov/providercommonerr.h" /* PROV_R_READ_KEY */
#include "encoder_local.h"

int ossl_prov_read_der(PROV_CTX *provctx, OSSL_CORE_BIO *cin,
                       unsigned char **data, long *len)
{
    BUF_MEM *mem = NULL;
    BIO *in = bio_new_from_core_bio(provctx, cin);
    int ok = (asn1_d2i_read_bio(in, &mem) >= 0);

    if (ok) {
        *data = (unsigned char *)mem->data;
        *len = (long)mem->length;
        OPENSSL_free(mem);
    }
    BIO_free(in);
    return ok;
}

int ossl_prov_read_pem(PROV_CTX *provctx, OSSL_CORE_BIO *cin,
                       char **pem_name, char **pem_header,
                       unsigned char **data, long *len)
{
    BIO *in = bio_new_from_core_bio(provctx, cin);
    int ok = (PEM_read_bio(in, pem_name, pem_header, data, len) > 0);

    BIO_free(in);
    return ok;
}

#ifndef OPENSSL_NO_DSA
EVP_PKEY *ossl_prov_read_msblob(PROV_CTX *provctx, OSSL_CORE_BIO *cin,
                                int *ispub)
{
    BIO *in = bio_new_from_core_bio(provctx, cin);
    EVP_PKEY *pkey = ossl_b2i_bio(in, ispub);

    BIO_free(in);
    return pkey;
}

# ifndef OPENSSL_NO_RC4
EVP_PKEY *ossl_prov_read_pvk(PROV_CTX *provctx, OSSL_CORE_BIO *cin,
                             OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    BIO *in = NULL;
    EVP_PKEY *pkey = NULL;
    struct ossl_passphrase_data_st pwdata;

    memset(&pwdata, 0, sizeof(pwdata));
    if (!ossl_pw_set_ossl_passphrase_cb(&pwdata, pw_cb, pw_cbarg))
        return NULL;

    in = bio_new_from_core_bio(provctx, cin);
    pkey = b2i_PVK_bio(in, ossl_pw_pem_password, &pwdata);
    BIO_free(in);

    return pkey;
}
# endif
#endif

int ossl_prov_der_from_p8(unsigned char **new_der, long *new_der_len,
                          unsigned char *input_der, long input_der_len,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    const unsigned char *derp;
    X509_SIG *p8 = NULL;
    int ok = 0;

    if (!ossl_assert(new_der != NULL && *new_der == NULL)
        || !ossl_assert(new_der_len != NULL))
        return 0;

    derp = input_der;
    if ((p8 = d2i_X509_SIG(NULL, &derp, input_der_len)) != NULL) {
        char pbuf[PEM_BUFSIZE];
        size_t plen = 0;

        if (!pw_cb(pbuf, sizeof(pbuf), &plen, NULL, pw_cbarg)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_READ_KEY);
        } else {
            const X509_ALGOR *alg = NULL;
            const ASN1_OCTET_STRING *oct = NULL;
            int len = 0;

            X509_SIG_get0(p8, &alg, &oct);
            if (PKCS12_pbe_crypt(alg, pbuf, plen, oct->data, oct->length,
                                 new_der, &len, 0) != NULL)
                ok = 1;
            *new_der_len = len;
        }
    }
    X509_SIG_free(p8);
    return ok;
}
