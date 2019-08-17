/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_MACROS_H
# define OPENSSL_MACROS_H

# ifndef OPENSSL_FUNC
#  if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#   define OPENSSL_FUNC __func__
#  elif defined(__STDC__) && defined(PEDANTIC)
#   define OPENSSL_FUNC "(PEDANTIC disallows function name)"
#  elif defined(_MSC_VER) || (defined(__GNUC__) && __GNUC__ >= 2)
#   define OPENSSL_FUNC __FUNCTION__
#  elif defined(__FUNCSIG__)
#   define OPENSSL_FUNC __FUNCSIG__
#  else
#   define OPENSSL_FUNC "(unknown function)"
#  endif
# endif

#endif  /* OPENSSL_MACROS_H */
