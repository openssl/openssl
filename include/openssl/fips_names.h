/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef OPENtls_FIPS_NAMES_H
# define OPENtls_FIPS_NAMES_H

# ifdef __cplusplus
extern "C" {
# endif

/*
 * Parameter names that the FIPS Provider defines
 */

/*
 * The calculated MAC of the module file (Used for FIPS Self Testing)
 * Type: Otls_PARAM_UTF8_STRING
 */
# define Otls_PROV_FIPS_PARAM_MODULE_MAC      "module-checksum"
/*
 * A version number for the fips install process (Used for FIPS Self Testing)
 * Type: Otls_PARAM_UTF8_STRING
 */
# define Otls_PROV_FIPS_PARAM_INSTALL_VERSION "install-version"
/*
 * The calculated MAC of the install status indicator (Used for FIPS Self Testing)
 * Type: Otls_PARAM_UTF8_STRING
 */
# define Otls_PROV_FIPS_PARAM_INSTALL_MAC     "install-checksum"
/*
 * The install status indicator (Used for FIPS Self Testing)
 * Type: Otls_PARAM_UTF8_STRING
 */
# define Otls_PROV_FIPS_PARAM_INSTALL_STATUS  "install-status"

# ifdef __cplusplus
}
# endif

#endif /* OPENtls_FIPS_NAMES_H */
