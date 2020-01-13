/*
 * Copyright 2001-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/crypto.h>
#include <opentls/opentlsconf.h>

#if defined(OPENtls_SYS_WIN32) || defined(OPENtls_SYS_VXWORKS) || defined(OPENtls_SYS_UEFI)

int OPENtls_issetugid(void)
{
    return 0;
}

#elif defined(__OpenBSD__) || (defined(__FreeBSD__) && __FreeBSD__ > 2) || defined(__DragonFly__)

# include <unistd.h>

int OPENtls_issetugid(void)
{
    return issetugid();
}

#else

# include <unistd.h>
# include <sys/types.h>

# if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#  if __GLIBC_PREREQ(2, 16)
#   include <sys/auxv.h>
#   define Otls_IMPLEMENT_GETAUXVAL
#  endif
# endif

int OPENtls_issetugid(void)
{
# ifdef Otls_IMPLEMENT_GETAUXVAL
    return getauxval(AT_SECURE) != 0;
# else
    return getuid() != geteuid() || getgid() != getegid();
# endif
}
#endif
