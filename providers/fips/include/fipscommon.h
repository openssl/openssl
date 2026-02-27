/*
 * Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifdef FIPS_MODULE
#include <openssl/types.h>

int ossl_fips_config_security_checks(OSSL_LIB_CTX *libctx);
int ossl_fips_config_tls1_prf_ems_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_no_short_mac(OSSL_LIB_CTX *libctx);
int ossl_fips_config_hmac_key_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_kmac_key_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_restricted_drbg_digests(OSSL_LIB_CTX *libctx);
int ossl_fips_config_signature_digest_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_hkdf_digest_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_tls13_kdf_digest_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_tls1_prf_digest_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_sshkdf_digest_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_sskdf_digest_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_x963kdf_digest_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_dsa_sign_disallowed(OSSL_LIB_CTX *libctx);
int ossl_fips_config_tdes_encrypt_disallowed(OSSL_LIB_CTX *libctx);
int ossl_fips_config_rsa_pkcs15_padding_disabled(OSSL_LIB_CTX *libctx);
int ossl_fips_config_rsa_pss_saltlen_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_rsa_sign_x931_disallowed(OSSL_LIB_CTX *libctx);
int ossl_fips_config_hkdf_key_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_kbkdf_key_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_tls13_kdf_key_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_tls1_prf_key_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_sshkdf_key_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_sskdf_key_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_x963kdf_key_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_x942kdf_key_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_pbkdf2_lower_bound_check(OSSL_LIB_CTX *libctx);
int ossl_fips_config_ecdh_cofactor_check(OSSL_LIB_CTX *libctx);

#endif
