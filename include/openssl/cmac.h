/*
 * Copyright 2010-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CMAC_H
# define OPENSSL_CMAC_H
# pragma once

# include <openssl/macros.h>
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define HEADER_CMAC_H
# endif

# ifndef OPENSSL_NO_CMAC

#  ifdef __cplusplus
extern "C" {
#  endif

#  include <openssl/evp.h>

#  ifndef OPENSSL_NO_DEPRECATED_3_0
/* Opaque */
typedef struct CMAC_CTX_st CMAC_CTX;
#  endif

DEPRECATEDIN_3_0(CMAC_CTX *CMAC_CTX_new(void))
DEPRECATEDIN_3_0(void CMAC_CTX_cleanup(CMAC_CTX *ctx))
DEPRECATEDIN_3_0(void CMAC_CTX_free(CMAC_CTX *ctx))
DEPRECATEDIN_3_0(EVP_CIPHER_CTX *CMAC_CTX_get0_cipher_ctx(CMAC_CTX *ctx))
DEPRECATEDIN_3_0(int CMAC_CTX_copy(CMAC_CTX *out, const CMAC_CTX *in))

DEPRECATEDIN_3_0(int CMAC_Init(CMAC_CTX *ctx, const void *key, size_t keylen,
              const EVP_CIPHER *cipher, ENGINE *impl))
DEPRECATEDIN_3_0(int CMAC_Update(CMAC_CTX *ctx, const void *data, size_t dlen))
DEPRECATEDIN_3_0(int CMAC_Final(CMAC_CTX *ctx, unsigned char *out,
                                size_t *poutlen))
DEPRECATEDIN_3_0(int CMAC_resume(CMAC_CTX *ctx))

#  ifdef  __cplusplus
}
#  endif

# endif
#endif
