/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_DECODER_H
# define OPENSSL_DECODER_H
# pragma once

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_STDIO
#  include <stdio.h>
# endif
# include <stdarg.h>
# include <stddef.h>
# include <openssl/decodererr.h>
# include <openssl/types.h>
# include <openssl/core.h>

# ifdef __cplusplus
extern "C" {
# endif

OSSL_DECODER_METHOD *OSSL_DECODER_METHOD_fetch(OSSL_LIB_CTX *libctx,
                                               const char *name,
                                               const char *properties);
int OSSL_DECODER_METHOD_up_ref(OSSL_DECODER_METHOD *encoder);
void OSSL_DECODER_METHOD_free(OSSL_DECODER_METHOD *encoder);

const OSSL_PROVIDER *
OSSL_DECODER_METHOD_provider(const OSSL_DECODER_METHOD *encoder);
const char *
OSSL_DECODER_METHOD_properties(const OSSL_DECODER_METHOD *encoder);
int OSSL_DECODER_METHOD_number(const OSSL_DECODER_METHOD *encoder);
int OSSL_DECODER_METHOD_is_a(const OSSL_DECODER_METHOD *encoder,
                             const char *name);

void
OSSL_DECODER_METHOD_do_all_provided(OSSL_LIB_CTX *libctx,
                                    void (*fn)(OSSL_DECODER_METHOD *encoder,
                                               void *arg),
                                    void *arg);
void OSSL_DECODER_METHOD_names_do_all(const OSSL_DECODER_METHOD *encoder,
                                      void (*fn)(const char *name, void *data),
                                      void *data);
const OSSL_PARAM *
OSSL_DECODER_METHOD_gettable_params(OSSL_DECODER_METHOD *dec_method);
int OSSL_DECODER_METHOD_get_params(OSSL_DECODER_METHOD *dec_method,
                                   OSSL_PARAM params[]);

const OSSL_PARAM *
OSSL_DECODER_METHOD_settable_ctx_params(OSSL_DECODER_METHOD *encoder);
OSSL_DECODER *OSSL_DECODER_new(void);
int OSSL_DECODER_set_params(OSSL_DECODER *decoder, const OSSL_PARAM params[]);
void OSSL_DECODER_free(OSSL_DECODER *decoder);

/* Utilities that help set specific parameters */
int OSSL_DECODER_set_passphrase(OSSL_DECODER *decoder,
                                const unsigned char *kstr, size_t klen);
int OSSL_DECODER_set_pem_password_cb(OSSL_DECODER *decoder,
                                     pem_password_cb *cb, void *cbarg);
int OSSL_DECODER_set_passphrase_cb(OSSL_DECODER *decoder,
                                   OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg);
int OSSL_DECODER_set_passphrase_ui(OSSL_DECODER *decoder,
                                   const UI_METHOD *ui_method, void *ui_data);

/*
 * Utilities to read the object to decode, with the result sent to cb.
 * These will discover all provided methods
 */

int OSSL_DECODER_set_selection(OSSL_DECODER *decoder, int selection);
int OSSL_DECODER_set_input_type(OSSL_DECODER *decoder, const char *input_type);
int OSSL_DECODER_set_input_structure(OSSL_DECODER *decoder,
                                     const char *input_structure);

/* Utilities to add decoder methods */
int OSSL_DECODER_add_method(OSSL_DECODER *decoder,
                            OSSL_DECODER_METHOD *decoder_meth);
int OSSL_DECODER_add_extra_methods(OSSL_DECODER *decoder,
                                   OSSL_LIB_CTX *libctx, const char *propq);
int OSSL_DECODER_get_num_methods(OSSL_DECODER *decoder);

typedef struct ossl_decoder_instance_st OSSL_DECODER_INSTANCE;
OSSL_DECODER_METHOD *
OSSL_DECODER_INSTANCE_get_method(OSSL_DECODER_INSTANCE *decoder_inst);
void *
OSSL_DECODER_INSTANCE_get_method_ctx(OSSL_DECODER_INSTANCE *decoder_inst);
const char *
OSSL_DECODER_INSTANCE_get_input_type(OSSL_DECODER_INSTANCE *decoder_inst);
const char *
OSSL_DECODER_INSTANCE_get_input_structure(OSSL_DECODER_INSTANCE *decoder_inst,
                                          int *was_set);

typedef int OSSL_DECODER_CONSTRUCT(OSSL_DECODER_INSTANCE *decoder_inst,
                                   const OSSL_PARAM *params,
                                   void *construct_data);
typedef void OSSL_DECODER_CLEANUP(void *construct_data);

int OSSL_DECODER_set_construct(OSSL_DECODER *decoder,
                               OSSL_DECODER_CONSTRUCT *construct);
int OSSL_DECODER_set_construct_data(OSSL_DECODER *decoder,
                                    void *construct_data);
int OSSL_DECODER_set_cleanup(OSSL_DECODER *decoder,
                             OSSL_DECODER_CLEANUP *cleanup);
OSSL_DECODER_CONSTRUCT *OSSL_DECODER_get_construct(OSSL_DECODER *decoder);
void *OSSL_DECODER_get_construct_data(OSSL_DECODER *decoder);
OSSL_DECODER_CLEANUP *OSSL_DECODER_get_cleanup(OSSL_DECODER *decoder);

int OSSL_DECODER_export(OSSL_DECODER_INSTANCE *decoder_inst,
                        void *reference, size_t reference_sz,
                        OSSL_CALLBACK *export_cb, void *export_cbarg);

int OSSL_DECODER_from_bio(OSSL_DECODER *decoder, BIO *in);
#ifndef OPENSSL_NO_STDIO
int OSSL_DECODER_from_fp(OSSL_DECODER *decoder, FILE *in);
#endif
int OSSL_DECODER_from_data(OSSL_DECODER *decoder, const unsigned char **pdata,
                           size_t *pdata_len);

/*
 * Create the OSSL_DECODER with an associated type.  This will perform
 * an implicit OSSL_DECODER_METHOD_fetch(), suitable for the object of that type.
 */
OSSL_DECODER *OSSL_DECODER_new_by_EVP_PKEY(EVP_PKEY **pkey,
                                           const char *input_type,
                                           const char *input_struct,
                                           const char *keytype, int selection,
                                           OSSL_LIB_CTX *libctx,
                                           const char *propquery);

# ifdef __cplusplus
}
# endif
#endif
