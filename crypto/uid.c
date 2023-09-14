/*
 * Copyright 2001-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/opensslconf.h>
#if defined (OPENSSL_NETCAP_ALLOW_ENV) && defined(__linux__)
#include <linux/capability.h>
#include <sys/types.h>
#include <sys/syscall.h>
#endif

#if defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_VXWORKS) || defined(OPENSSL_SYS_UEFI) || defined(__wasi__)

int OPENSSL_issetugid(void)
{
    return 0;
}

#elif defined(__OpenBSD__) || (defined(__FreeBSD__) && __FreeBSD__ > 2) || defined(__DragonFly__) || (defined(__GLIBC__) && defined(__FreeBSD_kernel__))

# include <unistd.h>

int OPENSSL_issetugid(void)
{
    return issetugid();
}

#else

# include <unistd.h>
# include <sys/types.h>

# if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#  if __GLIBC_PREREQ(2, 16)
#   include <sys/auxv.h>
#   define OSSL_IMPLEMENT_GETAUXVAL
#  endif
# elif defined(__ANDROID_API__)
/* see https://developer.android.google.cn/ndk/guides/cpu-features */
#  if __ANDROID_API__ >= 18
#   include <sys/auxv.h>
#   define OSSL_IMPLEMENT_GETAUXVAL
#  endif
# endif

/*
 * Allows for slightly more permissive environment variable retrieval. Requires capability checks
 */
#if defined (OPENSSL_NETCAP_ALLOW_ENV) && defined(__linux__)
/*
 * Tests to see if a process has ONLY the requested capability
 * see kernel/capability.c in the linux kernel source for more details
 * structs are defined in sys/capability.h
 */
int HasOnlyCapability(int capability)
{

    if (!cap_valid(capability)) {
        return 0;
    }

    struct __user_cap_data_struct cap_data[2];
    struct __user_cap_header_struct cap_header_data = {
        _LINUX_CAPABILITY_VERSION_3,
        getpid()};

    if (syscall(SYS_capget, &cap_header_data, &cap_data) != 0) {
        return 0;
    }

    if (capability < 32) {
        return cap_data[0].permitted == (CAP_TO_MASK(capability));
    }
    // Probably also need to check [1] - some capabilities are >32
    // to check for ONLY net_bind we need to ensure these are 0 also
    
    return cap_data[1].permitted == (CAP_TO_MASK(capability));
}
#endif

int OPENSSL_issetugid(void)
{
# ifdef OSSL_IMPLEMENT_GETAUXVAL
#   if defined (OPENSSL_NETCAP_ALLOW_ENV) && defined(__linux__)
      /* AT_SECURE is set if privileged. We allow this if ONLY NET_BIND capability set */
      int at_secure = getauxval(AT_SECURE);
      int hasNetBindServiceOnly = HasOnlyCapability(CAP_NET_BIND_SERVICE);
      return at_secure != 0 && !hasNetBindServiceOnly;
      //return getauxval(AT_SECURE) != 0 && !HasOnlyCapability(CAP_NET_BIND_SERVICE);
#   else
      return getauxval(AT_SECURE) != 0;
#   endif
# else
    return getuid() != geteuid() || getgid() != getegid();
# endif
}
#endif
