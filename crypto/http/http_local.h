/*
 * Copyright 2007-2020 The OpenSSL Project Authors. All Rights Reserved.
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

/* name aliases for legacy names with name prefix "OCSP_" */
typedef OCSP_REQ_CTX OSSL_HTTP_REQ_CTX;
/* functions meanwhile only used internally */
# define OSSL_HTTP_REQ_CTX_new         OCSP_REQ_CTX_new
# define OSSL_HTTP_REQ_CTX_free        OCSP_REQ_CTX_free
# define OSSL_HTTP_REQ_CTX_header      OCSP_REQ_CTX_http
# define OSSL_HTTP_REQ_CTX_add1_header OCSP_REQ_CTX_add1_header
# define OSSL_HTTP_REQ_CTX_i2d         OCSP_REQ_CTX_i2d
# define OSSL_HTTP_REQ_CTX_nbio        OCSP_REQ_CTX_nbio
# ifndef OPENSSL_NO_SOCK
#  define OSSL_HTTP_REQ_CTX_sendreq_d2i OCSP_REQ_CTX_nbio_d2i
# endif
/* functions that are meanwhile unused */
# define OSSL_HTTP_REQ_CTX_get0_mem_bio OCSP_REQ_CTX_get0_mem_bio /* undoc'd */
# define OSSL_HTTP_REQ_CTX_set_max_response_length OCSP_set_max_response_length

BIO *HTTP_asn1_item2bio(const ASN1_ITEM *it, ASN1_VALUE *val);
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

#endif /* !defined OSSL_CRYPTO_HTTP_LOCAL_H */
