/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_ENCODER_H
# define OPENSSL_ENCODER_H
# pragma once

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_STDIO
#  include <stdio.h>
# endif
# include <stdarg.h>
# include <stddef.h>
# include <openssl/encodererr.h>
# include <openssl/types.h>
# include <openssl/core.h>

# ifdef __cplusplus
extern "C" {
# endif

OSSL_ENCODER *OSSL_ENCODER_fetch(OPENSSL_CTX *libctx, const char *name,
                                 const char *properties);
int OSSL_ENCODER_up_ref(OSSL_ENCODER *encoder);
void OSSL_ENCODER_free(OSSL_ENCODER *encoder);

const OSSL_PROVIDER *OSSL_ENCODER_provider(const OSSL_ENCODER *encoder);
const char *OSSL_ENCODER_properties(const OSSL_ENCODER *encoder);
int OSSL_ENCODER_number(const OSSL_ENCODER *encoder);
int OSSL_ENCODER_is_a(const OSSL_ENCODER *encoder, const char *name);

void OSSL_ENCODER_do_all_provided(OPENSSL_CTX *libctx,
                                  void (*fn)(OSSL_ENCODER *encoder, void *arg),
                                  void *arg);
void OSSL_ENCODER_names_do_all(const OSSL_ENCODER *encoder,
                               void (*fn)(const char *name, void *data),
                               void *data);

const OSSL_PARAM *OSSL_ENCODER_settable_ctx_params(OSSL_ENCODER *encoder);
OSSL_ENCODER_CTX *OSSL_ENCODER_CTX_new(OSSL_ENCODER *encoder);
const OSSL_ENCODER *OSSL_ENCODER_CTX_get_encoder(OSSL_ENCODER_CTX *ctx);
int OSSL_ENCODER_CTX_set_params(OSSL_ENCODER_CTX *ctx,
                                const OSSL_PARAM params[]);
void OSSL_ENCODER_CTX_free(OSSL_ENCODER_CTX *ctx);

/* Utilities that help set specific parameters */
int OSSL_ENCODER_CTX_set_cipher(OSSL_ENCODER_CTX *ctx,
                                const char *cipher_name,
                                const char *propquery);
int OSSL_ENCODER_CTX_set_passphrase(OSSL_ENCODER_CTX *ctx,
                                    const unsigned char *kstr,
                                    size_t klen);
int OSSL_ENCODER_CTX_set_passphrase_cb(OSSL_ENCODER_CTX *ctx,
                                       pem_password_cb *cb, void *cbarg);
int OSSL_ENCODER_CTX_set_passphrase_ui(OSSL_ENCODER_CTX *ctx,
                                       const UI_METHOD *ui_method,
                                       void *ui_data);

/* Utilities to output the object to encode */
int OSSL_ENCODER_to_bio(OSSL_ENCODER_CTX *ctx, BIO *out);
#ifndef OPENSSL_NO_STDIO
int OSSL_ENCODER_to_fp(OSSL_ENCODER_CTX *ctx, FILE *fp);
#endif

/*
 * Create the OSSL_ENCODER_CTX with an associated type.  This will perform
 * an implicit OSSL_ENCODER_fetch(), suitable for the object of that type.
 * This is more useful than calling OSSL_ENCODER_CTX_new().
 */
OSSL_ENCODER_CTX *OSSL_ENCODER_CTX_new_by_EVP_PKEY(const EVP_PKEY *pkey,
                                                   const char *propquery);

/*
 * These macros define the last argument to pass to
 * OSSL_ENCODER_CTX_new_by_TYPE().
 */
# define OSSL_ENCODER_PUBKEY_TO_PEM_PQ "format=pem,type=public"
# define OSSL_ENCODER_PrivateKey_TO_PEM_PQ "format=pem,type=private"
# define OSSL_ENCODER_Parameters_TO_PEM_PQ "format=pem,type=parameters"

# define OSSL_ENCODER_PUBKEY_TO_DER_PQ "format=der,type=public"
# define OSSL_ENCODER_PrivateKey_TO_DER_PQ "format=der,type=private"
# define OSSL_ENCODER_Parameters_TO_DER_PQ "format=der,type=parameters"

/* Corresponding macros for text output */
# define OSSL_ENCODER_PUBKEY_TO_TEXT_PQ "format=text,type=public"
# define OSSL_ENCODER_PrivateKey_TO_TEXT_PQ "format=text,type=private"
# define OSSL_ENCODER_Parameters_TO_TEXT_PQ "format=text,type=parameters"

# ifdef __cplusplus
}
# endif
#endif
