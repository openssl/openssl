/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_APPS_APPS_KEYS_H
#define OSSL_APPS_APPS_KEYS_H

EVP_PKEY *load_key(const char *uri, int format, int maybe_stdin,
                   const char *pass, ENGINE *e, const char *desc);
int load_key_certs_crls(const char *uri, int maybe_stdin,
                        const char *pass, const char *desc,
                        EVP_PKEY **ppkey, EVP_PKEY **ppubkey,
                        EVP_PKEY **pparams,
                        X509 **pcert, STACK_OF(X509) **pcerts,
                        X509_CRL **pcrl, STACK_OF(X509_CRL) **pcrls);
int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value);
int do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey,
                        const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts);

#endif                          /* ! OSSL_APPS_APPS_KEYS_H */
