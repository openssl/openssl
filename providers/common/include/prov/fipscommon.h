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
int FIPS_restricted_drbg_digests_enabled(OSSL_LIB_CTX *libctx);
int FIPS_hkdf_digest_check(OSSL_LIB_CTX *libctx);
int FIPS_tls13_kdf_digest_check(OSSL_LIB_CTX *libctx);
int FIPS_tls1_prf_digest_check(OSSL_LIB_CTX *libctx);
int FIPS_sshkdf_digest_check(OSSL_LIB_CTX *libctx);
int FIPS_sskdf_digest_check(OSSL_LIB_CTX *libctx);
int FIPS_x963kdf_digest_check(OSSL_LIB_CTX *libctx);

#endif
