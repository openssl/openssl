/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef OPENtls_SERIALIZER_H
# define OPENtls_SERIALIZER_H
# pragma once

# include <opentls/opentlsconf.h>

# ifndef OPENtls_NO_STDIO
#  include <stdio.h>
# endif
# include <stdarg.h>
# include <stddef.h>
# include <opentls/serializererr.h>
# include <opentls/types.h>
# include <opentls/core.h>

# ifdef __cplusplus
extern "C" {
# endif

Otls_SERIALIZER *Otls_SERIALIZER_fetch(OPENtls_CTX *libctx,
                                       const char *name,
                                       const char *properties);
int Otls_SERIALIZER_up_ref(Otls_SERIALIZER *ser);
void Otls_SERIALIZER_free(Otls_SERIALIZER *ser);

const Otls_PROVIDER *Otls_SERIALIZER_provider(const Otls_SERIALIZER *ser);
const char *Otls_SERIALIZER_properties(const Otls_SERIALIZER *ser);
int Otls_SERIALIZER_number(const Otls_SERIALIZER *ser);
int Otls_SERIALIZER_is_a(const Otls_SERIALIZER *ser,
                         const char *name);

void Otls_SERIALIZER_do_all_provided(OPENtls_CTX *libctx,
                                     void (*fn)(Otls_SERIALIZER *ser,
                                                void *arg),
                                     void *arg);
void Otls_SERIALIZER_names_do_all(const Otls_SERIALIZER *ser,
                                  void (*fn)(const char *name, void *data),
                                  void *data);

const Otls_PARAM *Otls_SERIALIZER_settable_ctx_params(Otls_SERIALIZER *ser);
Otls_SERIALIZER_CTX *Otls_SERIALIZER_CTX_new(Otls_SERIALIZER *ser);
const Otls_SERIALIZER *
Otls_SERIALIZER_CTX_get_serializer(Otls_SERIALIZER_CTX *ctx);
int Otls_SERIALIZER_CTX_set_params(Otls_SERIALIZER_CTX *ctx,
                                   const Otls_PARAM params[]);
void Otls_SERIALIZER_CTX_free(Otls_SERIALIZER_CTX *ctx);

/* Utilities that help set specific parameters */
int Otls_SERIALIZER_CTX_set_cipher(Otls_SERIALIZER_CTX *ctx,
                                   const char *cipher_name,
                                   const char *propquery);
int Otls_SERIALIZER_CTX_set_passphrase(Otls_SERIALIZER_CTX *ctx,
                                       const unsigned char *kstr,
                                       size_t klen);
int Otls_SERIALIZER_CTX_set_passphrase_cb(Otls_SERIALIZER_CTX *ctx, int enc,
                                          pem_password_cb *cb, void *cbarg);
int Otls_SERIALIZER_CTX_set_passphrase_ui(Otls_SERIALIZER_CTX *ctx,
                                          const UI_METHOD *ui_method,
                                          void *ui_data);

/* Utilities to output the object to serialize */
int Otls_SERIALIZER_to_bio(Otls_SERIALIZER_CTX *ctx, BIO *out);
#ifndef OPENtls_NO_STDIO
int Otls_SERIALIZER_to_fp(Otls_SERIALIZER_CTX *ctx, FILE *fp);
#endif

/*
 * Create the Otls_SERIALIZER_CTX with an associated type.  This will perform
 * an implicit Otls_SERIALIZER_fetch(), suitable for the object of that type.
 * This is more useful than calling Otls_SERIALIZER_CTX_new().
 */
Otls_SERIALIZER_CTX *Otls_SERIALIZER_CTX_new_by_EVP_PKEY(const EVP_PKEY *pkey,
                                                         const char *propquery);

/*
 * These macros define the last argument to pass to
 * Otls_SERIALIZER_CTX_new_by_TYPE().
 */
# define Otls_SERIALIZER_PUBKEY_TO_PEM_PQ "format=pem,type=public"
# define Otls_SERIALIZER_PrivateKey_TO_PEM_PQ "format=pem,type=private"
# define Otls_SERIALIZER_Parameters_TO_PEM_PQ "format=pem,type=domainparams"

/* Corresponding macros for text output */
# define Otls_SERIALIZER_PUBKEY_TO_TEXT_PQ "format=text,type=public"
# define Otls_SERIALIZER_PrivateKey_TO_TEXT_PQ "format=text,type=private"
# define Otls_SERIALIZER_Parameters_TO_TEXT_PQ "format=text,type=domainparams"

# ifdef __cplusplus
}
# endif
#endif
