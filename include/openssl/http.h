/*
 * Copyright 2000-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Siemens AG 2018-2020
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_HTTP_H
# define OPENSSL_HTTP_H
# pragma once

# include <openssl/opensslconf.h>

# include <openssl/bio.h>
# include <openssl/asn1.h>
# include <openssl/conf.h>


# ifdef __cplusplus
extern "C" {
# endif

typedef BIO *(*OSSL_HTTP_bio_cb_t)(BIO *bio, void *arg, int connect, int detail);

# define OSSL_HTTP_NAME "http"
# define OSSL_HTTPS_NAME "https"
# define OSSL_HTTP_PREFIX OSSL_HTTP_NAME"://"
# define OSSL_HTTPS_PREFIX OSSL_HTTPS_NAME"://"
# define OSSL_HTTP_PORT "80"
# define OSSL_HTTPS_PORT "443"
# define OPENSSL_NO_PROXY "NO_PROXY"
# define OPENSSL_HTTP_PROXY "HTTP_PROXY"
# define OPENSSL_HTTPS_PROXY "HTTPS_PROXY"

#define HTTP_DEFAULT_MAX_LINE_LENGTH (4 * 1024)
#define HTTP_DEFAULT_MAX_RESP_LEN (100 * 1024)

OSSL_HTTP_REQ_CTX *OSSL_HTTP_REQ_CTX_new(BIO *wbio, BIO *rbio,
                                         int method_GET, int maxline,
                                         unsigned long max_resp_len,
                                         int timeout,
                                         const char *expected_content_type,
                                         int expect_asn1);
void OSSL_HTTP_REQ_CTX_free(OSSL_HTTP_REQ_CTX *rctx);
int OSSL_HTTP_REQ_CTX_set_request_line(OSSL_HTTP_REQ_CTX *rctx,
                                       const char *server, const char *port,
                                       const char *path);
int OSSL_HTTP_REQ_CTX_add1_header(OSSL_HTTP_REQ_CTX *rctx,
                                  const char *name, const char *value);
int OSSL_HTTP_REQ_CTX_i2d(OSSL_HTTP_REQ_CTX *rctx, const char *content_type,
                          const ASN1_ITEM *it, ASN1_VALUE *req);
int OSSL_HTTP_REQ_CTX_nbio(OSSL_HTTP_REQ_CTX *rctx);
ASN1_VALUE *OSSL_HTTP_REQ_CTX_sendreq_d2i(OSSL_HTTP_REQ_CTX *rctx,
                                          const ASN1_ITEM *it);
BIO *OSSL_HTTP_REQ_CTX_get0_mem_bio(const OSSL_HTTP_REQ_CTX *rctx);
void OSSL_HTTP_REQ_CTX_set_max_response_length(OSSL_HTTP_REQ_CTX *rctx,
                                               unsigned long len);

BIO *OSSL_HTTP_get(const char *url, const char *proxy, const char *no_proxy,
                   BIO *bio, BIO *rbio,
                   OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
                   const STACK_OF(CONF_VALUE) *headers,
                   int maxline, unsigned long max_resp_len, int timeout,
                   const char *expected_content_type, int expect_asn1);
ASN1_VALUE *OSSL_HTTP_get_asn1(const char *url,
                               const char *proxy, const char *no_proxy,
                               BIO *bio, BIO *rbio,
                               OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
                               const STACK_OF(CONF_VALUE) *headers,
                               int maxline, unsigned long max_resp_len,
                               int timeout, const char *expected_content_type,
                               const ASN1_ITEM *it);
ASN1_VALUE *OSSL_HTTP_post_asn1(const char *server, const char *port,
                                const char *path, int use_ssl,
                                const char *proxy, const char *no_proxy,
                                BIO *bio, BIO *rbio,
                                OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
                                const STACK_OF(CONF_VALUE) *headers,
                                const char *content_type,
                                const ASN1_VALUE *req, const ASN1_ITEM *req_it,
                                int maxline, unsigned long max_resp_len,
                                int timeout, const char *expected_ct,
                                const ASN1_ITEM *rsp_it);
BIO *OSSL_HTTP_transfer(const char *server, const char *port, const char *path,
                        int use_ssl, const char *proxy, const char *no_proxy,
                        BIO *bio, BIO *rbio,
                        OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
                        const STACK_OF(CONF_VALUE) *headers,
                        const char *content_type, BIO *req_mem,
                        int maxline, unsigned long max_resp_len, int timeout,
                        const char *expected_ct, int expect_asn1,
                        char **redirection_url);
int OSSL_HTTP_proxy_connect(BIO *bio, const char *server, const char *port,
                            const char *proxyuser, const char *proxypass,
                            int timeout, BIO *bio_err, const char *prog);

int OSSL_HTTP_parse_url(const char *url, char **phost, char **pport,
                        int *pport_num, char **ppath, int *pssl);

# ifdef  __cplusplus
}
# endif
#endif /* !defined(OPENSSL_HTTP_H) */
