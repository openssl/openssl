/*
 * Copyright 2019-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This file contains self test data required by FIPS 140-3 IG
 * 10.3.A Cryptographic Algorithm Self test Requirements
 *
 * Note that in the 'General CAST requirements': Note33 Allows individual
 * self tests for low level algorithms (such as digests) to be omitted, if
 * they are tested as part of a higher level algorithm (such as HMAC).
 */

extern const ST_KAT_DIGEST st_kat_digest_tests[];
extern int st_kat_digest_tests_size;
extern const ST_KAT_CIPHER st_kat_cipher_tests[];
extern int st_kat_cipher_tests_size;
#ifndef OPENSSL_NO_LMS
extern const ST_KAT_LMS st_kat_lms_test;
#endif
extern const ST_KAT_KDF st_kat_kdf_tests[];
extern int st_kat_kdf_tests_size;
extern const ST_KAT_DRBG st_kat_drbg_tests[];
extern int st_kat_drbg_tests_size;
#if !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_EC)
extern const ST_KAT_KAS st_kat_kas_tests[];
extern int st_kat_kas_tests_size;
#endif
extern const ST_KAT_SIGN st_kat_sign_tests[];
extern int st_kat_sign_tests_size;
#ifndef OPENSSL_NO_ML_KEM
extern const ST_KAT_KEM st_kat_kem_tests[];
extern int st_kat_kem_tests_size;
#endif
#if !defined(OPENSSL_NO_ML_KEM) || !defined(OPENSSL_NO_ML_DSA) || !defined(OPENSSL_NO_SLH_DSA)
extern const ST_KAT_ASYM_KEYGEN st_kat_asym_keygen_tests[];
extern int st_kat_asym_keygen_tests_size;
#endif
extern const ST_KAT_ASYM_CIPHER st_kat_asym_cipher_tests[];
extern int st_kat_asym_cipher_tests_size;
