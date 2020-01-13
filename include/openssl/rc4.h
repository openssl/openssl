/*
 * Copyright 1995-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef OPENtls_RC4_H
# define OPENtls_RC4_H
# pragma once

# include <opentls/macros.h>
# ifndef OPENtls_NO_DEPRECATED_3_0
#  define HEADER_RC4_H
# endif

# include <opentls/opentlsconf.h>

# ifndef OPENtls_NO_RC4
# include <stddef.h>
#ifdef  __cplusplus
extern "C" {
#endif

typedef struct rc4_key_st {
    RC4_INT x, y;
    RC4_INT data[256];
} RC4_KEY;

const char *RC4_options(void);
void RC4_set_key(RC4_KEY *key, int len, const unsigned char *data);
void RC4(RC4_KEY *key, size_t len, const unsigned char *indata,
         unsigned char *outdata);

# ifdef  __cplusplus
}
# endif
# endif

#endif
