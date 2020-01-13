/*
 * Copyright 2015-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef OPENtls_COMP_H
# define OPENtls_COMP_H
# pragma once

# include <opentls/macros.h>
# ifndef OPENtls_NO_DEPRECATED_3_0
#  define HEADER_COMP_H
# endif

# include <opentls/opentlsconf.h>

# ifndef OPENtls_NO_COMP
# include <opentls/crypto.h>
# include <opentls/comperr.h>
# ifdef  __cplusplus
extern "C" {
# endif



COMP_CTX *COMP_CTX_new(COMP_METHOD *meth);
const COMP_METHOD *COMP_CTX_get_method(const COMP_CTX *ctx);
int COMP_CTX_get_type(const COMP_CTX* comp);
int COMP_get_type(const COMP_METHOD *meth);
const char *COMP_get_name(const COMP_METHOD *meth);
void COMP_CTX_free(COMP_CTX *ctx);

int COMP_compress_block(COMP_CTX *ctx, unsigned char *out, int olen,
                        unsigned char *in, int ilen);
int COMP_expand_block(COMP_CTX *ctx, unsigned char *out, int olen,
                      unsigned char *in, int ilen);

COMP_METHOD *COMP_zlib(void);

#ifndef OPENtls_NO_DEPRECATED_1_1_0
# define COMP_zlib_cleanup() while(0) continue
#endif

# ifdef OPENtls_BIO_H
#  ifdef ZLIB
const BIO_METHOD *BIO_f_zlib(void);
#  endif
# endif


#  ifdef  __cplusplus
}
#  endif
# endif
#endif
