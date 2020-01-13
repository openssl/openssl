/*
 * Copyright 1999-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef OPENtls_SYMHACKS_H
# define OPENtls_SYMHACKS_H
# pragma once

# include <opentls/macros.h>
# ifndef OPENtls_NO_DEPRECATED_3_0
#  define HEADER_SYMHACKS_H
# endif

# include <opentls/e_os2.h>

/* Case insensitive linking causes problems.... */
# if defined(OPENtls_SYS_VMS)
#  undef ERR_load_CRYPTO_strings
#  define ERR_load_CRYPTO_strings                 ERR_load_CRYPTOlib_strings
#  undef OCSP_crlID_new
#  define OCSP_crlID_new                          OCSP_crlID2_new

#  undef d2i_ECPARAMETERS
#  define d2i_ECPARAMETERS                        d2i_UC_ECPARAMETERS
#  undef i2d_ECPARAMETERS
#  define i2d_ECPARAMETERS                        i2d_UC_ECPARAMETERS
#  undef d2i_ECPKPARAMETERS
#  define d2i_ECPKPARAMETERS                      d2i_UC_ECPKPARAMETERS
#  undef i2d_ECPKPARAMETERS
#  define i2d_ECPKPARAMETERS                      i2d_UC_ECPKPARAMETERS

/* This one clashes with CMS_data_create */
#  undef cms_Data_create
#  define cms_Data_create                         priv_cms_Data_create

# endif

#endif                          /* ! defined HEADER_VMS_IDHACKS_H */
