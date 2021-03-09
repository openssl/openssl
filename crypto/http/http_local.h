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

BIO *ossl_http_asn1_item2bio(const ASN1_ITEM *it, const ASN1_VALUE *val);

OSSL_HTTP_REQ_CTX
*ossl_http_req_ctx_new(BIO *wbio, BIO *rbio, int use_http_proxy,
                       const char *server, const char *port,
                       const char *path,
                       const STACK_OF(CONF_VALUE) *headers,
                       const char *content_type, BIO *req_mem,
                       int maxline, unsigned long max_resp_len,
                       int timeout,
                       const char *expected_content_type,
                       int expect_asn1);

int ossl_http_use_proxy(const char *no_proxy, const char *server);
const char *ossl_http_adapt_proxy(const char *proxy, const char *no_proxy,
                                  const char *server, int use_ssl);

#endif /* !defined(OSSL_CRYPTO_HTTP_LOCAL_H) */
