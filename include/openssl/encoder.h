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

OSSL_ENCODER_METHOD *OSSL_ENCODER_METHOD_fetch(OSSL_LIB_CTX *libctx,
                                               const char *name,
                                               const char *properties);
int OSSL_ENCODER_METHOD_up_ref(OSSL_ENCODER_METHOD *enc_method);
void OSSL_ENCODER_METHOD_free(OSSL_ENCODER_METHOD *enc_method);

const OSSL_PROVIDER *
OSSL_ENCODER_METHOD_provider(const OSSL_ENCODER_METHOD *enc_method);
const char *
OSSL_ENCODER_METHOD_properties(const OSSL_ENCODER_METHOD *enc_method);
int OSSL_ENCODER_METHOD_number(const OSSL_ENCODER_METHOD *enc_method);
int OSSL_ENCODER_METHOD_is_a(const OSSL_ENCODER_METHOD *enc_method,
                             const char *name);

void
OSSL_ENCODER_METHOD_do_all_provided(OSSL_LIB_CTX *libctx,
                                    void (*fn)(OSSL_ENCODER_METHOD *enc_method,
                                               void *arg),
                                    void *arg);
void OSSL_ENCODER_METHOD_names_do_all(const OSSL_ENCODER_METHOD *enc_method,
                                      void (*fn)(const char *name, void *data),
                                      void *data);
const OSSL_PARAM *
OSSL_ENCODER_METHOD_gettable_params(OSSL_ENCODER_METHOD *enc_method);
int OSSL_ENCODER_METHOD_get_params(OSSL_ENCODER_METHOD *enc_method,
                                   OSSL_PARAM params[]);

const OSSL_PARAM *
OSSL_ENCODER_METHOD_settable_ctx_params(OSSL_ENCODER_METHOD *enc_method);

OSSL_ENCODER *OSSL_ENCODER_new(void);
int OSSL_ENCODER_set_params(OSSL_ENCODER *encoder, const OSSL_PARAM params[]);
void OSSL_ENCODER_free(OSSL_ENCODER *encoder);

/* Utilities that help set specific parameters */
int OSSL_ENCODER_set_passphrase(OSSL_ENCODER *encoder,
                                const unsigned char *kstr, size_t klen);
int OSSL_ENCODER_set_pem_password_cb(OSSL_ENCODER *encoder,
                                     pem_password_cb *cb, void *cbarg);
int OSSL_ENCODER_set_passphrase_cb(OSSL_ENCODER *encoder,
                                   OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg);
int OSSL_ENCODER_set_passphrase_ui(OSSL_ENCODER *encoder,
                                   const UI_METHOD *ui_method, void *ui_data);
int OSSL_ENCODER_set_cipher(OSSL_ENCODER *encoder,
                            const char *cipher_name, const char *propquery);
int OSSL_ENCODER_set_selection(OSSL_ENCODER *encoder, int selection);
int OSSL_ENCODER_set_output_type(OSSL_ENCODER *encoder, const char *output_type);
int OSSL_ENCODER_set_output_structure(OSSL_ENCODER *encoder,
                                      const char *output_structure);

/* Utilities to add encoder methods */
int OSSL_ENCODER_add_method(OSSL_ENCODER *encoder,
                            OSSL_ENCODER_METHOD *encoder_meth);
int OSSL_ENCODER_add_extra_methods(OSSL_ENCODER *encoder,
                                   OSSL_LIB_CTX *libctx, const char *propq);
int OSSL_ENCODER_get_num_methods(OSSL_ENCODER *encoder);

typedef struct ossl_encoder_instance_st OSSL_ENCODER_INSTANCE;
OSSL_ENCODER_METHOD *
OSSL_ENCODER_INSTANCE_get_method(OSSL_ENCODER_INSTANCE *encoder_inst);
void *
OSSL_ENCODER_INSTANCE_get_method_ctx(OSSL_ENCODER_INSTANCE *encoder_inst);
const char *
OSSL_ENCODER_INSTANCE_get_input_type(OSSL_ENCODER_INSTANCE *encoder_inst);
const char *
OSSL_ENCODER_INSTANCE_get_output_type(OSSL_ENCODER_INSTANCE *encoder_inst);
const char *
OSSL_ENCODER_INSTANCE_get_output_structure(OSSL_ENCODER_INSTANCE *encoder_inst);

typedef const void *OSSL_ENCODER_CONSTRUCT(OSSL_ENCODER_INSTANCE *encoder_inst,
                                           void *construct_data);
typedef void OSSL_ENCODER_CLEANUP(void *construct_data);

int OSSL_ENCODER_set_construct(OSSL_ENCODER *encoder,
                               OSSL_ENCODER_CONSTRUCT *construct);
int OSSL_ENCODER_set_construct_data(OSSL_ENCODER *encoder, void *construct_data);
int OSSL_ENCODER_set_cleanup(OSSL_ENCODER *encoder,
                             OSSL_ENCODER_CLEANUP *cleanup);

/* Utilities to output the object to encode */
int OSSL_ENCODER_to_bio(OSSL_ENCODER *encoder, BIO *out);
#ifndef OPENSSL_NO_STDIO
int OSSL_ENCODER_to_fp(OSSL_ENCODER *encoder, FILE *fp);
#endif
int OSSL_ENCODER_to_data(OSSL_ENCODER *encoder, unsigned char **pdata,
                         size_t *pdata_len);

/*
 * Create the OSSL_ENCODER with an associated type.  This will perform
 * an implicit OSSL_ENCODER_fetch(), suitable for the object of that type.
 * This is more useful than calling OSSL_ENCODER_new().
 */
OSSL_ENCODER *OSSL_ENCODER_new_by_EVP_PKEY(const EVP_PKEY *pkey, int selection,
                                           const char *output_type,
                                           const char *output_struct,
                                           const char *propquery);

# ifdef __cplusplus
}
# endif
#endif
