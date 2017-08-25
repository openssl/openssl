/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include <openssl/rand.h>
#include "rand_lcl.h"

#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32)

# ifndef OPENSSL_RAND_SEED_OS
#  error "Unsupported seeding method configured; must be os"
# endif

# include <windows.h>
/* On Windows 7 or higher use BCrypt instead of the legacy CryptoAPI */
# if defined(_MSC_VER) && defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0601
#  define USE_BCRYPTGENRANDOM
# endif

# ifdef USE_BCRYPTGENRANDOM
#  include <bcrypt.h>
#  pragma comment(lib, "bcrypt.lib")
#  ifndef STATUS_SUCCESS
#   define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#  endif
# else
#  include <wincrypt.h>
/*
 * Intel hardware RNG CSP -- available from
 * http://developer.intel.com/design/security/rng/redist_license.htm
 */
#  define PROV_INTEL_SEC 22
#  define INTEL_DEF_PROV L"Intel Hardware Cryptographic Service Provider"
# endif

int RAND_poll_ex(RAND_poll_cb rand_add, void *arg)
{
# ifndef USE_BCRYPTGENRANDOM
    HCRYPTPROV hProvider;
    int ok = 0;
# endif
    BYTE buf[RANDOMNESS_NEEDED];

# ifdef OPENSSL_RAND_SEED_RDTSC
    rand_read_tsc(cb, arg);
# endif
# ifdef OPENSSL_RAND_SEED_RDCPU
    if (rand_read_cpu(cb, arg))
        return 1;
# endif

# ifdef USE_BCRYPTGENRANDOM
    if (BCryptGenRandom(NULL, buf, (ULONG)sizeof(buf),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) == STATUS_SUCCESS) {
        rand_add(arg, buf, sizeof(buf), sizeof(buf));
        return 1;
    }
# else
    /* poll the CryptoAPI PRNG */
    if (CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT | CRYPT_SILENT) != 0) {
        if (CryptGenRandom(hProvider, (DWORD)sizeof(buf), buf) != 0) {
            rand_add(arg, buf, sizeof(buf), sizeof(buf));
            ok = 1;
        }
        CryptReleaseContext(hProvider, 0);
        if (ok)
            return 1;
    }

    /* poll the Pentium PRG with CryptoAPI */
    if (CryptAcquireContextW(&hProvider, NULL, INTEL_DEF_PROV, PROV_INTEL_SEC,
                             CRYPT_VERIFYCONTEXT | CRYPT_SILENT) != 0) {
        if (CryptGenRandom(hProvider, (DWORD)sizeof(buf), buf) != 0) {
            rand_add(arg, buf, sizeof(buf), sizeof(buf));
            ok = 1;
        }
        CryptReleaseContext(hProvider, 0);
        if (ok)
            return 1;
    }
# endif

    return 0;
}

# if OPENSSL_API_COMPAT < 0x10100000L
int RAND_event(UINT iMsg, WPARAM wParam, LPARAM lParam)
{
    RAND_poll();
    return RAND_status();
}

void RAND_screen(void)
{
    RAND_poll();
}
# endif

#endif
