/*
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_EVP_H
# define OPENSSL_EVP_H
# pragma once

# include <openssl/macros.h>
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define HEADER_ENVELOPE_H
# endif

# include <stdarg.h>

# ifndef OPENSSL_NO_STDIO
#  include <stdio.h>
# endif

# include <openssl/opensslconf.h>
# include <openssl/core.h>
# include <openssl/core_dispatch.h>
# include <openssl/symhacks.h>
# include <openssl/bio.h>
# include <openssl/evperr.h>
# include <openssl/params.h>
# include <openssl/asym.h>
# include <openssl/deprecated.h>
# include <openssl/cipher.h>
# include <openssl/digest.h>
# include <openssl/encode.h>
# include <openssl/exchange.h>
# include <openssl/kem.h>
# include <openssl/keygen.h>
# include <openssl/keymgmt.h>
# include <openssl/mac.h>
# include <openssl/pbe.h>
# include <openssl/pkey.h>
# include <openssl/pkey_asn1.h>
# include <openssl/rand.h>
# include <openssl/signature.h>

#ifdef  __cplusplus
extern "C" {
#endif

int EVP_set_default_properties(OSSL_LIB_CTX *libctx, const char *propq);
int EVP_default_properties_is_fips_enabled(OSSL_LIB_CTX *libctx);
int EVP_default_properties_enable_fips(OSSL_LIB_CTX *libctx, int enable);

# ifdef CONST_STRICT
void BIO_set_md(BIO *, const EVP_MD *md);
# else
#  define BIO_set_md(b,md)          BIO_ctrl(b,BIO_C_SET_MD,0,(void *)(md))
# endif
# define BIO_get_md(b,mdp)          BIO_ctrl(b,BIO_C_GET_MD,0,(mdp))
# define BIO_get_md_ctx(b,mdcp)     BIO_ctrl(b,BIO_C_GET_MD_CTX,0,(mdcp))
# define BIO_set_md_ctx(b,mdcp)     BIO_ctrl(b,BIO_C_SET_MD_CTX,0,(mdcp))
# define BIO_get_cipher_status(b)   BIO_ctrl(b,BIO_C_GET_CIPHER_STATUS,0,NULL)
# define BIO_get_cipher_ctx(b,c_pp) BIO_ctrl(b,BIO_C_GET_CIPHER_CTX,0,(c_pp))

int EVP_read_pw_string(char *buf, int length, const char *prompt, int verify);
int EVP_read_pw_string_min(char *buf, int minlen, int maxlen,
                           const char *prompt, int verify);
void EVP_set_pw_prompt(const char *prompt);
char *EVP_get_pw_prompt(void);

const BIO_METHOD *BIO_f_md(void);
const BIO_METHOD *BIO_f_base64(void);
const BIO_METHOD *BIO_f_cipher(void);
const BIO_METHOD *BIO_f_reliable(void);
__owur int BIO_set_cipher(BIO *b, const EVP_CIPHER *c, const unsigned char *k,
                          const unsigned char *i, int enc);

void EVP_add_alg_module(void);

# ifdef  __cplusplus
}
# endif
#endif
