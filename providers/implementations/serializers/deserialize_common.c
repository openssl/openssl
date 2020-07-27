/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include "internal/cryptlib.h"
#include "crypto/asn1.h"
#include "prov/bio.h"               /* ossl_prov_bio_printf() */
#include "prov/providercommonerr.h" /* PROV_R_READ_KEY */
#include "serializer_local.h"

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
