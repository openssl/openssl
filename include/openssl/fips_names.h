/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_FIPS_NAMES_H
# define OPENSSL_FIPS_NAMES_H
# pragma once

# ifdef __cplusplus
extern "C" {
# endif

/*
 * Parameter names that the FIPS Provider defines
 */

/*
 * The calculated MAC of the module file (Used for FIPS Self Testing)
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_MODULE_MAC      "module-mac"
/*
 * A version number for the fips install process (Used for FIPS Self Testing)
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_INSTALL_VERSION "install-version"
/*
 * The calculated MAC of the install status indicator (Used for FIPS Self Testing)
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_INSTALL_MAC     "install-mac"
/*
 * The install status indicator (Used for FIPS Self Testing)
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_INSTALL_STATUS  "install-status"

/*
 * A boolean that determines if the FIPS conditional test errors result in
 * the module entering an error state.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_CONDITIONAL_ERRORS "conditional-errors"

/*
 * A boolean that determines if the runtime FIPS security checks are performed.
 * This is enabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_SECURITY_CHECKS "security-checks"

/*
 * A boolean that determines if the runtime FIPS check for TLS1_PRF EMS is performed.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_TLS1_PRF_EMS_CHECK "tls1-prf-ems-check"

/*
 * A boolean that determines if Ed448 and Ed25519 are forbidden to process
 * a pre-hashed message or not.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_EDDSA_NO_VERIFY_DIGESTED "eddsa-no-verify-digested"
/*
 * A boolean that determines if the runtime FIPS check for undersized MAC output
 * is performed.
 * This is enabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
#define OSSL_PROV_FIPS_PARAM_NO_SHORT_MAC "no-short-mac"

/*
 * A boolean that determines if truncated digests can be used with Hash and HMAC
 * DRBGs.  FIPS 140-3 IG D.R disallows such use for efficiency rather than
 * security reasons.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_DRBG_TRUNC_DIGEST "drbg-no-trunc-md"

/*
 * A boolean that determines if the digest algorithm used as part of a
 * signature algorithm is in the approved list.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_SIGNATURE_DIGEST_CHECK "signature-digest-check"

/*
 * A boolean that determines if the runtime FIPS digest check for HKDF is
 * performed.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_HKDF_DIGEST_CHECK "hkdf-digest-check"

/*
 * A boolean that determines if the runtime FIPS digest check for TLS13 KDF is
 * performed.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_TLS13_KDF_DIGEST_CHECK "tls13-kdf-digest-check"

/*
 * A boolean that determines if the runtime FIPS digest check for TLS1_PRF is
 * performed.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_TLS1_PRF_DIGEST_CHECK "tls1-prf-digest-check"

/*
 * A boolean that determines if the runtime FIPS digest check for SSHKDF is
 * performed.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_SSHKDF_DIGEST_CHECK "sshkdf-digest-check"

/*
 * A boolean that determines if the runtime FIPS digest check for SSKDF is
 * performed.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_SSKDF_DIGEST_CHECK "sskdf-digest-check"

/*
 * A boolean that determines if the runtime FIPS digest check for X963KDF is
 * performed.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_X963KDF_DIGEST_CHECK "x963kdf-digest-check"

/*
 * A boolean that determines if DSA signing operations are allowed.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_DSA_SIGN_DISABLED "dsa-sign-disabled"

/*
 * A boolean that determines if Triple-DES encryption operations are allowed.
 * See SP800-131A r2 for further information.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_TDES_ENCRYPT_DISABLED "tdes-encrypt-disabled"

/*
 * A boolean that determines if PKCS#1 v1.5 padding is allowed for key
 * agreement and transport operations.
 * See SP800-131A r2 for further information.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_RSA_PKCS15_PADDING_DISABLED \
            "rsa-pkcs15-padding-disabled"
/*
 * A boolean that determines if X9.31 padding can be used for RSA signing.
 * X9.31 RSA has been removed from FIPS 186-5, and is no longer approved for
 * signing. it may still be used for verification for legacy purposes.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_RSA_SIGN_X931_PAD_DISABLED "rsa-sign-x931-pad-disabled"

/*
 * A boolean that determines if the runtime FIPS key check for HKDF is
 * performed.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_HKDF_KEY_CHECK "hkdf-key-check"

/*
 * A boolean that determines if the runtime FIPS key check for KBKDF is
 * performed.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_KBKDF_KEY_CHECK "kbkdf-key-check"

/*
 * A boolean that determines if the runtime FIPS key check for TLS13 KDF is
 * performed.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_TLS13_KDF_KEY_CHECK "tls13-kdf-key-check"

/*
 * A boolean that determines if the runtime FIPS key check for TLS1_PRF is
 * performed.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_TLS1_PRF_KEY_CHECK "tls1-prf-key-check"

/*
 * A boolean that determines if the runtime FIPS key check for SSHKDF is
 * performed.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_SSHKDF_KEY_CHECK "sshkdf-key-check"

/*
 * A boolean that determines if the runtime FIPS key check for SSKDF is
 * performed.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_SSKDF_KEY_CHECK "sskdf-key-check"

/*
 * A boolean that determines if the runtime FIPS key check for X963KDF is
 * performed.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_X963KDF_KEY_CHECK "x963kdf-key-check"

/*
 * A boolean that determines if the runtime lower bound check for PBKDF2 is
 * performed.
 * This is enabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_PBKDF2_LOWER_BOUND_CHECK "pbkdf2-lower-bound-check"

# ifdef __cplusplus
}
# endif

#endif /* OPENSSL_FIPS_NAMES_H */
