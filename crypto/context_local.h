/*
 * Copyright 2019-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>

void *provider_store_new(OSSL_LIB_CTX *);
void *property_string_data_new(OSSL_LIB_CTX *);
void *stored_namemap_new(OSSL_LIB_CTX *);
void *property_defns_new(OSSL_LIB_CTX *);
void *ossl_ctx_global_properties_new(OSSL_LIB_CTX *);
void *rand_ossl_ctx_new(OSSL_LIB_CTX *);
void *prov_conf_ossl_ctx_new(OSSL_LIB_CTX *);
void *bio_core_globals_new(OSSL_LIB_CTX *);
void *child_prov_ossl_ctx_new(OSSL_LIB_CTX *);
void *decoder_store_new(OSSL_LIB_CTX *);
void *loader_store_new(OSSL_LIB_CTX *);
void *encoder_store_new(OSSL_LIB_CTX *);
void *prov_drbg_nonce_ossl_ctx_new(OSSL_LIB_CTX *);
void *self_test_set_callback_new(OSSL_LIB_CTX *);
void *rand_crng_ossl_ctx_new(OSSL_LIB_CTX *);
void *thread_event_ossl_ctx_new(OSSL_LIB_CTX *);

void provider_store_free(void *);
void property_string_data_free(void *);
void stored_namemap_free(void *);
void property_defns_free(void *);
void ossl_ctx_global_properties_free(void *);
void rand_ossl_ctx_free(void *);
void prov_conf_ossl_ctx_free(void *);
void bio_core_globals_free(void *);
void child_prov_ossl_ctx_free(void *);
void decoder_store_free(void *);
void loader_store_free(void *);
void encoder_store_free(void *);
void prov_drbg_nonce_ossl_ctx_free(void *);
void self_test_set_callback_free(void *);
void rand_crng_ossl_ctx_free(void *);
void thread_event_ossl_ctx_free(void *);
