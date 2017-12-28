/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_APPS_LOCL_H
# define HEADER_APPS_LOCL_H

# include "e_os.h" /* struct timeval for DTLS */
# include "opt.h"
# include "progs.h"

/* Variables defined in openssl.c */

extern BIO *bio_in;
extern BIO *bio_out;
extern BIO *bio_err;

/* Functions used in openssl.c only */

/*
 * VMS C only for now, implemented in vms_decc_init.c
 * If other C compilers forget to terminate argv with NULL, this function
 * can be re-used.
 */
char **copy_argv(int *argc, char *argv[]);
/*
 * Win32-specific argv initialization that splits OS-supplied UNICODE
 * command line string to array of UTF8-encoded strings.
 */
void win32_utf8argv(int *argc, char **argv[]);


/* Function defined in genpkey.c and also used in dgst.c */
int init_gen_str(EVP_PKEY_CTX **pctx,
                 const char *algname, ENGINE *e, int do_param);

/* Functions defined in req.c and also used in ca.c or x509.c */
int do_X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md,
                 STACK_OF(OPENSSL_STRING) *sigopts);
int do_X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md,
                     STACK_OF(OPENSSL_STRING) *sigopts);
int do_X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md,
                     STACK_OF(OPENSSL_STRING) *sigopts);

/* Function defined in ocsp.c and also used in s_server.c */
# ifndef OPENSSL_NO_OCSP
OCSP_RESPONSE *process_responder(OCSP_REQUEST *req,
                                 const char *host, const char *path,
                                 const char *port, int use_ssl,
                                 STACK_OF(CONF_VALUE) *headers,
                                 int req_timeout);
# endif

/* Function defined in ca.c and also used in ocsp.c */
int unpack_revinfo(ASN1_TIME **prevtm, int *preason, ASN1_OBJECT **phold,
                   ASN1_GENERALIZEDTIME **pinvtm, const char *str);

#endif
