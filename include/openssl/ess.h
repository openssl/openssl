/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_ESS_H
# define HEADER_ESS_H

# include <openssl/opensslconf.h>

# ifdef  __cplusplus
extern "C" {
# endif
# include <openssl/safestack.h>
# include <openssl/x509.h>
# include <openssl/esserr.h>

typedef struct ESS_issuer_serial ESS_ISSUER_SERIAL;
typedef struct ESS_cert_id ESS_CERT_ID;
typedef struct ESS_signing_cert ESS_SIGNING_CERT;

DEFINE_STACK_OF(ESS_CERT_ID)

typedef struct ESS_signing_cert_v2_st ESS_SIGNING_CERT_V2;
typedef struct ESS_cert_id_v2_st ESS_CERT_ID_V2;

DEFINE_STACK_OF(ESS_CERT_ID_V2)

ESS_ISSUER_SERIAL *ESS_ISSUER_SERIAL_new(void);
void ESS_ISSUER_SERIAL_free(ESS_ISSUER_SERIAL *a);
int i2d_ESS_ISSUER_SERIAL(const ESS_ISSUER_SERIAL *a, unsigned char **pp);
ESS_ISSUER_SERIAL *d2i_ESS_ISSUER_SERIAL(ESS_ISSUER_SERIAL **a,
                                         const unsigned char **pp,
                                         long length);
ESS_ISSUER_SERIAL *ESS_ISSUER_SERIAL_dup(ESS_ISSUER_SERIAL *a);

ESS_CERT_ID *ESS_CERT_ID_new(void);
void ESS_CERT_ID_free(ESS_CERT_ID *a);
int i2d_ESS_CERT_ID(const ESS_CERT_ID *a, unsigned char **pp);
ESS_CERT_ID *d2i_ESS_CERT_ID(ESS_CERT_ID **a, const unsigned char **pp,
                             long length);
ESS_CERT_ID *ESS_CERT_ID_dup(ESS_CERT_ID *a);

ESS_SIGNING_CERT *ESS_SIGNING_CERT_new(void);
void ESS_SIGNING_CERT_free(ESS_SIGNING_CERT *a);
int i2d_ESS_SIGNING_CERT(const ESS_SIGNING_CERT *a, unsigned char **pp);
ESS_SIGNING_CERT *d2i_ESS_SIGNING_CERT(ESS_SIGNING_CERT **a,
                                       const unsigned char **pp, long length);
ESS_SIGNING_CERT *ESS_SIGNING_CERT_dup(ESS_SIGNING_CERT *a);
ESS_SIGNING_CERT *ESS_SIGNING_CERT_new_init(X509 *signcert,
                                            STACK_OF(X509) *certs,
                                            int issuer_needed);

ESS_CERT_ID_V2 *ESS_CERT_ID_V2_new(void);
void ESS_CERT_ID_V2_free(ESS_CERT_ID_V2 *a);
int i2d_ESS_CERT_ID_V2(const ESS_CERT_ID_V2 *a, unsigned char **pp);
ESS_CERT_ID_V2 *d2i_ESS_CERT_ID_V2(ESS_CERT_ID_V2 **a,
                                   const unsigned char **pp, long length);
ESS_CERT_ID_V2 *ESS_CERT_ID_V2_dup(ESS_CERT_ID_V2 *a);

ESS_SIGNING_CERT_V2 *ESS_SIGNING_CERT_V2_new(void);
void ESS_SIGNING_CERT_V2_free(ESS_SIGNING_CERT_V2 *a);
int i2d_ESS_SIGNING_CERT_V2(const ESS_SIGNING_CERT_V2 *a, unsigned char **pp);
ESS_SIGNING_CERT_V2 *d2i_ESS_SIGNING_CERT_V2(ESS_SIGNING_CERT_V2 **a,
                                             const unsigned char **pp,
                                             long length);
ESS_SIGNING_CERT_V2 *ESS_SIGNING_CERT_V2_dup(ESS_SIGNING_CERT_V2 *a);
ESS_SIGNING_CERT_V2 *ESS_SIGNING_CERT_V2_new_init(const EVP_MD *hash_alg,
                                                  X509 *signcert,
                                                  STACK_OF(X509) *certs,
                                                  int issuer_needed);

# ifdef  __cplusplus
}
# endif
#endif
