/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ML_KEM_TYPES_H
# define ML_KEM_TYPES_H
# pragma once

# ifndef OPENSSL_NO_ML_KEM

typedef struct ossl_ml_kem_scalar_st ossl_ml_kem_scalar;

/*
 * Combine a prefix, the ML-KEM variant bitsize and a suffix, to produce a C
 * symbol name.
 */
#  define ossl_ml_kem_name(v, suffix) ossl_ml_kem_##v##_##suffix

/* Opaque outside the implementation code */
#  define DECLARE_VARIANT_TYPES(v) \
    typedef struct ossl_ml_kem_name(v,vector_st) \
        ossl_ml_kem_name(v,vector); \
    typedef struct ossl_ml_kem_name(v,matrix_st) \
        ossl_ml_kem_name(v,matrix); \
    typedef struct ossl_ml_kem_name(v,public_key_st) \
        ossl_ml_kem_name(v,public_key); \
    typedef struct ossl_ml_kem_name(v,private_key_st) \
        ossl_ml_kem_name(v,private_key)
DECLARE_VARIANT_TYPES(512);
DECLARE_VARIANT_TYPES(768);
DECLARE_VARIANT_TYPES(1024);
# undef DECLARE_VARIANT_TYPES
# undef ossl_ml_kem_name

# endif
#endif
