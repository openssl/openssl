/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_APPS_APP_X509_H
#define OSSL_APPS_APP_X509_H

#include "openssl/x509.h"

int set_cert_times(X509 *x, const char *startdate, const char *enddate,
                   int days);
int set_crl_lastupdate(X509_CRL *crl, const char *lastupdate);
int set_crl_nextupdate(X509_CRL *crl, const char *nextupdate,
                       long days, long hours, long secs);

int do_X509_verify(X509 *x, EVP_PKEY *pkey, STACK_OF(OPENSSL_STRING) *vfyopts);
int do_X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md,
                     STACK_OF(OPENSSL_STRING) *sigopts);
int do_X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md,
                     STACK_OF(OPENSSL_STRING) *sigopts);
void store_setup_crl_download(X509_STORE *st);

int x509_ctrl_string(X509 *x, const char *value);
int copy_extensions(X509 *x, X509_REQ *req, int copy_type);
X509_REQ *load_csr(const char *file, int format, const char *desc);
X509 *load_cert_pass(const char *uri, int maybe_stdin,
                     const char *pass, const char *desc);

X509_CRL *load_crl(const char *uri, const char *desc);
X509_NAME *parse_name(const char *str, int chtype, int multirdn,
                      const char *desc);

int x509_req_ctrl_string(X509_REQ *x, const char *value);
int do_X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md,
                 STACK_OF(OPENSSL_STRING) *sigopts, X509V3_CTX *ext_ctx);
int do_X509_REQ_verify(X509_REQ *x, EVP_PKEY *pkey,
                       STACK_OF(OPENSSL_STRING) *vfyopts);

#endif                          /* ! OSSL_APPS_APP_X509_H */
