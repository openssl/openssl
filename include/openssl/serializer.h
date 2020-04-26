/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_SERIALIZER_H
# define OPENSSL_SERIALIZER_H
# pragma once

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_STDIO
#  include <stdio.h>
# endif
# include <stdarg.h>
# include <stddef.h>
# include <openssl/serializererr.h>
# include <openssl/types.h>
# include <openssl/core.h>

# ifdef __cplusplus
extern "C" {
# endif

OSSL_SERIALIZER *OSSL_SERIALIZER_fetch(OPENSSL_CTX *libctx,
                                       const char *name,
                                       const char *properties);
int OSSL_SERIALIZER_up_ref(OSSL_SERIALIZER *ser);
void OSSL_SERIALIZER_free(OSSL_SERIALIZER *ser);

const OSSL_PROVIDER *OSSL_SERIALIZER_provider(const OSSL_SERIALIZER *ser);
const char *OSSL_SERIALIZER_properties(const OSSL_SERIALIZER *ser);
int OSSL_SERIALIZER_number(const OSSL_SERIALIZER *ser);
int OSSL_SERIALIZER_is_a(const OSSL_SERIALIZER *ser,
                         const char *name);

void OSSL_SERIALIZER_do_all_provided(OPENSSL_CTX *libctx,
                                     void (*fn)(OSSL_SERIALIZER *ser,
                                                void *arg),
                                     void *arg);
void OSSL_SERIALIZER_names_do_all(const OSSL_SERIALIZER *ser,
                                  void (*fn)(const char *name, void *data),
                                  void *data);

const OSSL_PARAM *OSSL_SERIALIZER_settable_ctx_params(OSSL_SERIALIZER *ser);
OSSL_SERIALIZER_CTX *OSSL_SERIALIZER_CTX_new(OSSL_SERIALIZER *ser);
const OSSL_SERIALIZER *
OSSL_SERIALIZER_CTX_get_serializer(OSSL_SERIALIZER_CTX *ctx);
int OSSL_SERIALIZER_CTX_set_params(OSSL_SERIALIZER_CTX *ctx,
                                   const OSSL_PARAM params[]);
void OSSL_SERIALIZER_CTX_free(OSSL_SERIALIZER_CTX *ctx);

/* Utilities that help set specific parameters */
int OSSL_SERIALIZER_CTX_set_cipher(OSSL_SERIALIZER_CTX *ctx,
                                   const char *cipher_name,
                                   const char *propquery);
int OSSL_SERIALIZER_CTX_set_passphrase(OSSL_SERIALIZER_CTX *ctx,
                                       const unsigned char *kstr,
                                       size_t klen);
int OSSL_SERIALIZER_CTX_set_passphrase_cb(OSSL_SERIALIZER_CTX *ctx, int enc,
                                          pem_password_cb *cb, void *cbarg);
int OSSL_SERIALIZER_CTX_set_passphrase_ui(OSSL_SERIALIZER_CTX *ctx,
                                          const UI_METHOD *ui_method,
                                          void *ui_data);

/* Utilities to output the object to serialize */
int OSSL_SERIALIZER_to_bio(OSSL_SERIALIZER_CTX *ctx, BIO *out);
#ifndef OPENSSL_NO_STDIO
int OSSL_SERIALIZER_to_fp(OSSL_SERIALIZER_CTX *ctx, FILE *fp);
#endif

/*
 * Create the OSSL_SERIALIZER_CTX with an associated type.  This will perform
 * an implicit OSSL_SERIALIZER_fetch(), suitable for the object of that type.
 * This is more useful than calling OSSL_SERIALIZER_CTX_new().
 */
OSSL_SERIALIZER_CTX *OSSL_SERIALIZER_CTX_new_by_EVP_PKEY(const EVP_PKEY *pkey,
                                                         const char *propquery);

/*
 * These macros define the last argument to pass to
 * OSSL_SERIALIZER_CTX_new_by_TYPE().
 */
# define OSSL_SERIALIZER_PUBKEY_TO_PEM_PQ "format=pem,type=public"
# define OSSL_SERIALIZER_PrivateKey_TO_PEM_PQ "format=pem,type=private"
# define OSSL_SERIALIZER_Parameters_TO_PEM_PQ "format=pem,type=parameters"

# define OSSL_SERIALIZER_PUBKEY_TO_DER_PQ "format=der,type=public"
# define OSSL_SERIALIZER_PrivateKey_TO_DER_PQ "format=der,type=private"
# define OSSL_SERIALIZER_Parameters_TO_DER_PQ "format=der,type=parameters"

/* Corresponding macros for text output */
# define OSSL_SERIALIZER_PUBKEY_TO_TEXT_PQ "format=text,type=public"
# define OSSL_SERIALIZER_PrivateKey_TO_TEXT_PQ "format=text,type=private"
# define OSSL_SERIALIZER_Parameters_TO_TEXT_PQ "format=text,type=parameters"

# ifdef __cplusplus
}
# endif
#endif
