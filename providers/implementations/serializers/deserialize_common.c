/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include "crypto/asn1.h"
#include "prov/bio.h"
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
