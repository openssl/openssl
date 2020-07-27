/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_DESERIALIZER_H
# define OPENSSL_DESERIALIZER_H
# pragma once

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_STDIO
#  include <stdio.h>
# endif
# include <stdarg.h>
# include <stddef.h>
# include <openssl/deserializererr.h>
# include <openssl/types.h>
# include <openssl/core.h>

# ifdef __cplusplus
extern "C" {
# endif

OSSL_DESERIALIZER *OSSL_DESERIALIZER_fetch(OPENSSL_CTX *libctx,
                                           const char *name,
                                           const char *properties);
int OSSL_DESERIALIZER_up_ref(OSSL_DESERIALIZER *ser);
void OSSL_DESERIALIZER_free(OSSL_DESERIALIZER *ser);

const OSSL_PROVIDER *OSSL_DESERIALIZER_provider(const OSSL_DESERIALIZER *ser);
const char *OSSL_DESERIALIZER_properties(const OSSL_DESERIALIZER *ser);
int OSSL_DESERIALIZER_number(const OSSL_DESERIALIZER *ser);
int OSSL_DESERIALIZER_is_a(const OSSL_DESERIALIZER *ser,
                           const char *name);

void OSSL_DESERIALIZER_do_all_provided(OPENSSL_CTX *libctx,
                                       void (*fn)(OSSL_DESERIALIZER *ser,
                                                  void *arg),
                                       void *arg);
void OSSL_DESERIALIZER_names_do_all(const OSSL_DESERIALIZER *ser,
                                    void (*fn)(const char *name, void *data),
                                    void *data);
const OSSL_PARAM *OSSL_DESERIALIZER_gettable_params(OSSL_DESERIALIZER *deser);
int OSSL_DESERIALIZER_get_params(OSSL_DESERIALIZER *deser, OSSL_PARAM params[]);

const OSSL_PARAM *OSSL_DESERIALIZER_settable_ctx_params(OSSL_DESERIALIZER *ser);
OSSL_DESERIALIZER_CTX *OSSL_DESERIALIZER_CTX_new(void);
int OSSL_DESERIALIZER_CTX_set_params(OSSL_DESERIALIZER_CTX *ctx,
                                     const OSSL_PARAM params[]);
void OSSL_DESERIALIZER_CTX_free(OSSL_DESERIALIZER_CTX *ctx);

/* Utilities that help set specific parameters */
int OSSL_DESERIALIZER_CTX_set_passphrase(OSSL_DESERIALIZER_CTX *ctx,
                                         const unsigned char *kstr,
                                         size_t klen);
int OSSL_DESERIALIZER_CTX_set_pem_password_cb(OSSL_DESERIALIZER_CTX *ctx,
                                              pem_password_cb *cb,
                                              void *cbarg);
int OSSL_DESERIALIZER_CTX_set_passphrase_ui(OSSL_DESERIALIZER_CTX *ctx,
                                            const UI_METHOD *ui_method,
                                            void *ui_data);

/*
 * Utilities to read the object to deserialize, with the result sent to cb.
 * These will discover all provided methods
 */

int OSSL_DESERIALIZER_CTX_set_input_type(OSSL_DESERIALIZER_CTX *ctx,
                                         const char *input_type);
int OSSL_DESERIALIZER_CTX_add_deserializer(OSSL_DESERIALIZER_CTX *ctx,
                                           OSSL_DESERIALIZER *deser);
int OSSL_DESERIALIZER_CTX_add_extra(OSSL_DESERIALIZER_CTX *ctx,
                                    OPENSSL_CTX *libctx, const char *propq);
int OSSL_DESERIALIZER_CTX_num_deserializers(OSSL_DESERIALIZER_CTX *ctx);

typedef struct ossl_deserializer_instance_st OSSL_DESERIALIZER_INSTANCE;
OSSL_DESERIALIZER *OSSL_DESERIALIZER_INSTANCE_deserializer
    (OSSL_DESERIALIZER_INSTANCE *deser_inst);
void *OSSL_DESERIALIZER_INSTANCE_deserializer_ctx
    (OSSL_DESERIALIZER_INSTANCE *deser_inst);

typedef int (OSSL_DESERIALIZER_CONSTRUCT)
    (OSSL_DESERIALIZER_INSTANCE *deser_inst,
     const OSSL_PARAM *params, void *construct_data);
typedef void (OSSL_DESERIALIZER_CLEANUP)(void *construct_data);

int OSSL_DESERIALIZER_CTX_set_construct(OSSL_DESERIALIZER_CTX *ctx,
                                        OSSL_DESERIALIZER_CONSTRUCT *construct);
int OSSL_DESERIALIZER_CTX_set_construct_data(OSSL_DESERIALIZER_CTX *ctx,
                                             void *construct_data);
int OSSL_DESERIALIZER_CTX_set_cleanup(OSSL_DESERIALIZER_CTX *ctx,
                                      OSSL_DESERIALIZER_CLEANUP *cleanup);
OSSL_DESERIALIZER_CONSTRUCT *
OSSL_DESERIALIZER_CTX_get_construct(OSSL_DESERIALIZER_CTX *ctx);
void *OSSL_DESERIALIZER_CTX_get_construct_data(OSSL_DESERIALIZER_CTX *ctx);
OSSL_DESERIALIZER_CLEANUP *
OSSL_DESERIALIZER_CTX_get_cleanup(OSSL_DESERIALIZER_CTX *ctx);

int OSSL_DESERIALIZER_export(OSSL_DESERIALIZER_INSTANCE *deser_inst,
                             void *reference, size_t reference_sz,
                             OSSL_CALLBACK *export_cb, void *export_cbarg);

int OSSL_DESERIALIZER_from_bio(OSSL_DESERIALIZER_CTX *ctx, BIO *in);
#ifndef OPENSSL_NO_STDIO
int OSSL_DESERIALIZER_from_fp(OSSL_DESERIALIZER_CTX *ctx, FILE *in);
#endif

/*
 * Create the OSSL_DESERIALIZER_CTX with an associated type.  This will perform
 * an implicit OSSL_DESERIALIZER_fetch(), suitable for the object of that type.
 */
OSSL_DESERIALIZER_CTX *
OSSL_DESERIALIZER_CTX_new_by_EVP_PKEY(EVP_PKEY **pkey, const char *input_type,
                                      OPENSSL_CTX *libctx,
                                      const char *propquery);

# ifdef __cplusplus
}
# endif
#endif
