/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef Otls_INTERNAL_SYMHACKS_H
# define Otls_INTERNAL_SYMHACKS_H

# include <opentls/e_os2.h>

# if defined(OPENtls_SYS_VMS)

/* otls_provider_available vs Otls_PROVIDER_available */
#  undef otls_provider_available
#  define otls_provider_available                 otls_int_prov_available
/* otls_provider_gettable_params vs Otls_PROVIDER_gettable_params */
#  undef otls_provider_gettable_params
#  define otls_provider_gettable_params            otls_int_prov_gettable_params
/* otls_provider_get_params vs Otls_PROVIDER_get_params */
#  undef otls_provider_get_params
#  define otls_provider_get_params                otls_int_prov_get_params

# endif

#endif                          /* ! defined HEADER_VMS_IDHACKS_H */
