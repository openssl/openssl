/*
 * Copyright 1999-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef OPENtls_EBCDIC_H
# define OPENtls_EBCDIC_H
# pragma once

# include <opentls/macros.h>
# ifndef OPENtls_NO_DEPRECATED_3_0
#  define HEADER_EBCDIC_H
# endif

# include <stdlib.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* Avoid name clashes with other applications */
# define os_toascii   _opentls_os_toascii
# define os_toebcdic  _opentls_os_toebcdic
# define ebcdic2ascii _opentls_ebcdic2ascii
# define ascii2ebcdic _opentls_ascii2ebcdic

extern const unsigned char os_toascii[256];
extern const unsigned char os_toebcdic[256];
void *ebcdic2ascii(void *dest, const void *srce, size_t count);
void *ascii2ebcdic(void *dest, const void *srce, size_t count);

#ifdef  __cplusplus
}
#endif
#endif
