/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_SYMHACKS_H
# define OSSL_INTERNAL_SYMHACKS_H

# include <openssl/e_os2.h>

# if defined(OPENSSL_SYS_VMS)

/* ossl_provider_get_param_types vs OSSL_PROVIDER_get_param_types */
#  undef ossl_provider_get_param_types
#  define ossl_provider_get_param_types           ossl_int_prov_get_param_types
/* ossl_provider_get_params vs OSSL_PROVIDER_get_params */
#  undef ossl_provider_get_params
#  define ossl_provider_get_params                ossl_int_prov_get_params

# endif

#endif                          /* ! defined HEADER_VMS_IDHACKS_H */
