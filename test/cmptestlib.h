/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2018
 * Copyright Siemens AG 2015-2018
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * CMP tests by Martin Peylo, Tobias Pankert, and David von Oheimb.
 */

#ifndef HEADER_CMP_TEST_LIB_H
# define HEADER_CMP_TEST_LIB_H

# include <openssl/cmp.h>
# include <openssl/pem.h>
# include <openssl/rand.h>
# include "testutil.h"

# ifndef OPENSSL_NO_CMP
#  define CMP_TEST_REFVALUE_LENGTH 15 /* arbitary value */
EVP_PKEY *load_pem_key(const char *file);
X509 *load_pem_cert(const char *file);
X509_REQ *load_csr(const char *file);
OSSL_CMP_MSG *load_pkimsg(const char *file);
int valid_asn1_encoding(const OSSL_CMP_MSG *msg);
EVP_PKEY *gen_rsa(void);
int STACK_OF_X509_cmp(const STACK_OF(X509) *sk1, const STACK_OF(X509) *sk2);
int STACK_OF_X509_push1(STACK_OF(X509) *sk, X509 *cert);
# endif

#endif /* HEADER_CMP_TEST_LIB_H */
