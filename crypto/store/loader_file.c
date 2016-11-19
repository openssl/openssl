/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/store.h>
#include "internal/asn1_int.h"
#include "store_local.h"

static STACK_OF(STORE_INFO) *file_loader(const char *authority,
                                         const char *path,
                                         const char *query,
                                         const char *fragment,
                                         pem_password_cb *pw_callback,
                                         void *pw_callback_data)
{
    BIO *file = NULL;
    BIO *buff = NULL;
    char peekbuf[4096];
    STACK_OF(STORE_INFO) *result = NULL;
    STORE_INFO *store_info = NULL;
    BUF_MEM *mem = NULL;

    if (authority != NULL) {
        STOREerr(STORE_F_FILE_LOADER, STORE_R_URI_AUTHORITY_UNSUPPORED);
        return NULL;
    }
    /*
     * Future development may allow a query to select the appropriate PEM
     * object in case a PEM file is loaded.
     */
    if (query != NULL) {
        STOREerr(STORE_F_FILE_LOADER, STORE_R_URI_QUERY_UNSUPPORED);
        return NULL;
    }
    /*
     * Future development may allow a numeric fragment to select which
     * object to return in case a PEM file is loaded.
     */
    if (fragment != NULL) {
        STOREerr(STORE_F_FILE_LOADER, STORE_R_URI_FRAGMENT_UNSUPPORED);
        return NULL;
    }

    if ((result = sk_STORE_INFO_new_null()) == NULL) {
        goto memerr;
    }

    if ((buff = BIO_new(BIO_f_buffer())) == NULL)
        goto err;
    if ((file = BIO_new_file(path, "rb")) == NULL) {
        BIO_free(buff);
        goto err;
    }
    file = BIO_push(buff, file);
    if (BIO_buffer_peek(file, peekbuf, sizeof(peekbuf)-1) > 0
        && (peekbuf[sizeof(peekbuf)-1] = '\0', 1)
        && strstr(peekbuf, "-----BEGIN ") != NULL) {
        STACK_OF(X509_INFO) *x509_infos =
            PEM_X509_INFO_read_bio(file, NULL, pw_callback, pw_callback_data);
        int i;

        if (x509_infos == NULL)
            goto err;
        for(i = 0; i < sk_X509_INFO_num(x509_infos); i++) {
            X509_INFO *x = sk_X509_INFO_value(x509_infos, i);

            if (x->x509 != NULL
                && ((store_info = STORE_INFO_new_CERT(x->x509)) == NULL
                    || sk_STORE_INFO_push(result, store_info) == 0))
                goto memerr;
            if (x->crl != NULL
                && ((store_info = STORE_INFO_new_CRL(x->crl)) == NULL
                    || sk_STORE_INFO_push(result, store_info) == 0))
                goto memerr;
            if (x->x_pkey != NULL
                && ((store_info = STORE_INFO_new_PKEY(x->x_pkey->dec_pkey)) == NULL
                    || sk_STORE_INFO_push(result, store_info) == 0))
                goto memerr;
            store_info = NULL;
        }
    } else {
        int len;
        EVP_PKEY *pkey = NULL;
        X509 *x509 = NULL;
        X509_CRL *crl = NULL;
        const unsigned char *data = NULL;

        if ((len = asn1_d2i_read_bio(file, &mem)) < 0)
            goto err;
        data = (unsigned char *)mem->data;
        if (d2i_AutoPrivateKey(&pkey, &data, len) != NULL)
            store_info = STORE_INFO_new_PKEY(pkey);
        else if (d2i_PUBKEY(&pkey, &data, len) != NULL)
            store_info = STORE_INFO_new_PKEY(pkey);
        else if (d2i_X509(&x509, &data, len) != NULL)
            store_info = STORE_INFO_new_CERT(x509);
        else if (d2i_X509_CRL(&crl, &data, len) != NULL)
            store_info = STORE_INFO_new_CRL(crl);
        else {
            ERR_clear_error();
            STOREerr(STORE_F_FILE_LOADER, STORE_R_UNSUPPORED_DATA_FORMAT);
            ERR_add_error_data(2, "File=", path);
            goto err;
        }

        if (store_info == NULL
            || sk_STORE_INFO_push(result, store_info) == 0) {
            goto memerr;
        }
        store_info = NULL;
    }

    BIO_free_all(file);
    BUF_MEM_free(mem);
    return result;
 memerr:
    STOREerr(STORE_F_FILE_LOADER, ERR_R_MALLOC_FAILURE);
 err:
    BIO_free_all(file);
    BUF_MEM_free(mem);
    STORE_INFO_free(store_info);
    sk_STORE_INFO_pop_free(result, STORE_INFO_free);
    return NULL;
}

SCHEME_LOADER store_file_loader = { 1, "file", file_loader };
