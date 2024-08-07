/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifdef FIPS_MODULE
# include <openssl/types.h>

int FIPS_security_check_enabled(OSSL_LIB_CTX *libctx);
int FIPS_tls_prf_ems_check(OSSL_LIB_CTX *libctx);
int FIPS_no_short_mac(OSSL_LIB_CTX *libctx);
int FIPS_hmac_key_check(OSSL_LIB_CTX *libctx);
int FIPS_kmac_key_check(OSSL_LIB_CTX *libctx);
int FIPS_restricted_drbg_digests_enabled(OSSL_LIB_CTX *libctx);
int FIPS_fips_signature_digest_check(OSSL_LIB_CTX *libctx);
int FIPS_hkdf_digest_check(OSSL_LIB_CTX *libctx);
int FIPS_tls13_kdf_digest_check(OSSL_LIB_CTX *libctx);
int FIPS_tls1_prf_digest_check(OSSL_LIB_CTX *libctx);
int FIPS_sshkdf_digest_check(OSSL_LIB_CTX *libctx);
int FIPS_sskdf_digest_check(OSSL_LIB_CTX *libctx);
int FIPS_x963kdf_digest_check(OSSL_LIB_CTX *libctx);
int FIPS_dsa_sign_check(OSSL_LIB_CTX *libctx);
int FIPS_tdes_encrypt_check(OSSL_LIB_CTX *libctx);
int FIPS_rsa_pkcs15_padding_disabled(OSSL_LIB_CTX *libctx);
int FIPS_rsa_pss_saltlen_check(OSSL_LIB_CTX *libctx);
int FIPS_rsa_sign_x931_disallowed(OSSL_LIB_CTX *libctx);
int FIPS_hkdf_key_check(OSSL_LIB_CTX *libctx);
int FIPS_kbkdf_key_check(OSSL_LIB_CTX *libctx);
int FIPS_tls13_kdf_key_check(OSSL_LIB_CTX *libctx);
int FIPS_tls1_prf_key_check(OSSL_LIB_CTX *libctx);
int FIPS_sshkdf_key_check(OSSL_LIB_CTX *libctx);
int FIPS_sskdf_key_check(OSSL_LIB_CTX *libctx);
int FIPS_x963kdf_key_check(OSSL_LIB_CTX *libctx);
int FIPS_pbkdf2_lower_bound_check(OSSL_LIB_CTX *libctx);
int FIPS_ecdh_cofactor_check(OSSL_LIB_CTX *libctx);
#endif
