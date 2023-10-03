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
 * A boolean that determines if truncated digests can be used with Hash and HMAC
 * DRBGs.  FIPS 140-3 IG D.R disallows such use for efficiency rather than
 * security reasons.
 * This is disabled by default.
 * Type: OSSL_PARAM_UTF8_STRING
 */
# define OSSL_PROV_FIPS_PARAM_DRBG_TRUNC_DIGEST  "drbg-no-trunc-md"

/*
 * A Boolean that determines if KMAC length checks should be enforced or not.
 * SP 800-131Ar2 section 10 mandates a minimum key length of 112 for both
 * generation and verification.  SP 800-185 section 8.4.2 mandates a minimum
 * of 32 bits of output.
 */
# define OSSL_PROV_FIPS_PARAM_KMAC_LENGTH_CHECKS "kmac-length-checks"

# ifdef __cplusplus
}
# endif

#endif /* OPENSSL_FIPS_NAMES_H */
