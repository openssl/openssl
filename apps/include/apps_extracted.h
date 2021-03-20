/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_APPS_APPS_EXTRACTED_H
#define OSSL_APPS_APPS_EXTRACTED_H

#include "openssl/x509.h"

//extern char *default_config_file; /* may be "" */
//BIO *dup_bio_in(int format);
//BIO *dup_bio_out(int format);
//BIO *dup_bio_err(int format);
//BIO *bio_open_owner(const char *filename, int format, int private);
//BIO *bio_open_default(const char *filename, char mode, int format);
//BIO *bio_open_default_quiet(const char *filename, char mode, int format);
//CONF *app_load_config_bio(BIO *in, const char *filename);
//#define app_load_config(filename) app_load_config_internal(filename, 0)
//#define app_load_config_quiet(filename) app_load_config_internal(filename, 1)
//CONF *app_load_config_internal(const char *filename, int quiet);
//CONF *app_load_config_verbose(const char *filename, int verbose);
//int app_load_modules(const CONF *config);
void unbuffer(FILE *fp);

int set_cert_times(X509 *x, const char *startdate, const char *enddate,
                   int days);
int set_crl_lastupdate(X509_CRL *crl, const char *lastupdate);
int set_crl_nextupdate(X509_CRL *crl, const char *nextupdate,
                       long days, long hours, long secs);

//int set_nameopt(const char *arg);
//unsigned long get_nameopt(void);
//int set_cert_ex(unsigned long *flags, const char *arg);
//int set_name_ex(unsigned long *flags, const char *arg);
//int set_ext_copy(int *copy_type, const char *arg);
int copy_extensions(X509 *x, X509_REQ *req, int copy_type);
//int app_passwd(const char *arg1, const char *arg2, char **pass1, char **pass2);
//int add_oid_section(CONF *conf);
X509_REQ *load_csr(const char *file, int format, const char *desc);
X509 *load_cert_pass(const char *uri, int maybe_stdin,
                     const char *pass, const char *desc);
//void cleanse(char *str);

EVP_PKEY *load_key(const char *uri, int format, int maybe_stdin,
                   const char *pass, ENGINE *e, const char *desc);
int load_key_certs_crls(const char *uri, int maybe_stdin,
                        const char *pass, const char *desc,
                        EVP_PKEY **ppkey, EVP_PKEY **ppubkey,
                        EVP_PKEY **pparams,
                        X509 **pcert, STACK_OF(X509) **pcerts,
                        X509_CRL **pcrl, STACK_OF(X509_CRL) **pcrls);

void release_engine(ENGINE *e);

int parse_yesno(const char *str, int def);
X509_NAME *parse_name(const char *str, int chtype, int multirdn,
                      const char *desc);

int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value);
int x509_req_ctrl_string(X509_REQ *x, const char *value);
int do_X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md,
                 STACK_OF(OPENSSL_STRING) *sigopts, X509V3_CTX *ext_ctx);
int do_X509_REQ_verify(X509_REQ *x, EVP_PKEY *pkey,
                       STACK_OF(OPENSSL_STRING) *vfyopts);

//int app_isdir(const char *);

//OSSL_LIB_CTX *app_create_libctx(void);
//OSSL_LIB_CTX *app_get0_libctx(void);
//int app_provider_load(OSSL_LIB_CTX *libctx, const char *provider_name);
//void app_providers_cleanup(void);
//int app_set_propq(const char *arg);

//const char *app_get0_propq(void);

#endif                          /* ! OSSL_APPS_APPS_EXTRACTED_H */
