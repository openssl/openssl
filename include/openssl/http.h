/*
 * Copyright 2000-2020 The OpenSSL Project Authors. All Rights Reserved.
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
# ifndef OPENSSL_NO_SOCK
BIO *OSSL_HTTP_get(const char *url, const char *proxy, const char *proxy_port,
                   BIO *bio, BIO *rbio,
                   OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
                   const STACK_OF(CONF_VALUE) *headers,
                   int maxline, unsigned long max_resp_len, int timeout,
                   const char *expected_content_type, int expect_asn1);
ASN1_VALUE *OSSL_HTTP_get_asn1(const char *url,
                               const char *proxy, const char *proxy_port,
                               BIO *bio, BIO *rbio,
                               OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
                               const STACK_OF(CONF_VALUE) *headers,
                               int maxline, unsigned long max_resp_len,
                               int timeout, const char *expected_content_type,
                               const ASN1_ITEM *it);
ASN1_VALUE *OSSL_HTTP_post_asn1(const char *server, const char *port,
                                const char *path, int use_ssl,
                                const char *proxy, const char *proxy_port,
                                BIO *bio, BIO *rbio,
                                OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
                                const STACK_OF(CONF_VALUE) *headers,
                                const char *content_type,
                                ASN1_VALUE *req, const ASN1_ITEM *req_it,
                                int maxline, unsigned long max_resp_len,
                                int timeout, const char *expected_ct,
                                const ASN1_ITEM *rsp_it);
BIO *OSSL_HTTP_transfer(const char *server, const char *port, const char *path,
                        int use_ssl, const char *proxy, const char *proxy_port,
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
# endif
int OSSL_HTTP_parse_url(const char *url, char **phost, char **pport,
                        char **ppath, int *pssl);

# ifdef  __cplusplus
}
# endif
#endif /* !defined OPENSSL_HTTP_H */
