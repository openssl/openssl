/*
 * Copyright 2007-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Siemens AG 2018-2020
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_HTTP_LOCAL_H
# define OSSL_CRYPTO_HTTP_LOCAL_H

# include <openssl/ocsp.h>

BIO *HTTP_asn1_item2bio(const ASN1_ITEM *it, const ASN1_VALUE *val);
OSSL_HTTP_REQ_CTX *HTTP_REQ_CTX_new(BIO *wbio, BIO *rbio, int use_http_proxy,
                                    const char *server, const char *port,
                                    const char *path,
                                    const STACK_OF(CONF_VALUE) *headers,
                                    const char *content_type, BIO *req_mem,
                                    int maxline, unsigned long max_resp_len,
                                    int timeout,
                                    const char *expected_content_type,
                                    int expect_asn1);
ASN1_VALUE *HTTP_sendreq_bio(BIO *bio, OSSL_HTTP_bio_cb_t bio_update_fn,
                             void *arg, const char *server, const char *port,
                             const char *path, int use_ssl, int use_proxy,
                             const STACK_OF(CONF_VALUE) *headers,
                             const char *content_type,
                             ASN1_VALUE *req, const ASN1_ITEM *req_it,
                             int maxline, unsigned long max_resp_len,
                             int timeout, const ASN1_ITEM *rsp_it);
int http_use_proxy(const char *no_proxy, const char *server);
const char *http_adapt_proxy(const char *proxy, const char *no_proxy,
                             const char *server, int use_ssl);

#endif /* !defined(OSSL_CRYPTO_HTTP_LOCAL_H) */
