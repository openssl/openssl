/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_COMP_H
# define OPENSSL_COMP_H
# pragma once
# include <openssl/macros.h>
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define HEADER_COMP_H
# endif

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_COMP
#  include <openssl/crypto.h>
#  include <openssl/comperr.h>
#  ifdef  __cplusplus
extern "C" {
#  endif

#  ifndef OPENSSL_NO_DEPRECATED_3_0
OSSL_DEPRECATEDIN_3_0 COMP_CTX *COMP_CTX_new(COMP_METHOD *meth);
OSSL_DEPRECATEDIN_3_0 const COMP_METHOD *COMP_CTX_get_method(
        const COMP_CTX *ctx);
OSSL_DEPRECATEDIN_3_0 int COMP_CTX_get_type(const COMP_CTX* comp);
OSSL_DEPRECATEDIN_3_0 int COMP_get_type(const COMP_METHOD *meth);
OSSL_DEPRECATEDIN_3_0 const char *COMP_get_name(const COMP_METHOD *meth);
OSSL_DEPRECATEDIN_3_0 void COMP_CTX_free(COMP_CTX *ctx);
OSSL_DEPRECATEDIN_3_0 int COMP_compress_block(
        COMP_CTX *ctx, unsigned char *out, int olen,
        unsigned char *in, int ilen);
OSSL_DEPRECATEDIN_3_0 int COMP_expand_block(
        COMP_CTX *ctx, unsigned char *out, int olen,
        unsigned char *in, int ilen);
OSSL_DEPRECATEDIN_3_0 COMP_METHOD *COMP_zlib(void);
#   ifdef OPENSSL_BIO_H
#    ifdef ZLIB
OSSL_DEPRECATEDIN_3_0 const BIO_METHOD *BIO_f_zlib(void);
#    endif
#   endif
#  endif

#  ifndef OPENSSL_NO_DEPRECATED_1_1_0
#   define COMP_zlib_cleanup() while(0) continue
#  endif

#  ifdef  __cplusplus
}
#  endif
# endif
#endif
