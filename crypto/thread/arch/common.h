/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/configuration.h>
#include <openssl/e_os2.h>

#if defined(_WIN32)
# include <windows.h>
#endif

#if defined(OPENSSL_THREADS) && defined(OPENSSL_SYS_UNIX)
# define OPENSSL_THREADS_POSIX
#elif defined(OPENSSL_THREADS) && defined(OPENSSL_SYS_WINDOWS) && \
    defined(_WIN32_WINNT)
# if _WIN32_WINNT >= 0x0600
#  define OPENSSL_THREADS_WINNT
# else
# define OPENSSL_THREADS_NONE
# endif
#else
# define OPENSSL_THREADS_NONE
#endif

