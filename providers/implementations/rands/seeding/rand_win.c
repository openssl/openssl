/*
 * Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/e_os.h" /* For windows.h */
#include "internal/cryptlib.h"
#include <openssl/rand.h>
#include "crypto/rand_pool.h"
#include "crypto/rand.h"
#include "prov/seeding.h"

#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32)

#ifndef OPENSSL_RAND_SEED_OS
#error "Unsupported seeding method configured; must be os"
#endif

/* On Windows Vista or higher use BCrypt instead of the legacy CryptoAPI */
#if defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0600 \
    && ((defined(_MSC_VER) && _MSC_VER > 1500)      \
        || (defined(__MINGW64_VERSION_MAJOR) && __MINGW64_VERSION_MAJOR >= 2))
#define USE_BCRYPTGENRANDOM
#endif

#ifdef USE_BCRYPTGENRANDOM
#include <bcrypt.h>
#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#else
#include <wincrypt.h>
/*
 * Intel hardware RNG CSP -- available from
 * http://developer.intel.com/design/security/rng/redist_license.htm
 */
#  define PROV_INTEL_SEC 22
#  define INTEL_DEF_PROV TEXT("Intel Hardware Cryptographic Service Provider")
# endif

// *** iProgram's Compatibility Stuff ***
#define IPROGRAMS_COMPAT_STUFF
#ifdef IPROGRAMS_COMPAT_STUFF

// TODO: Does this stuff run in multiple threads?
static int s_bIsStuffInitted = 0;
typedef BOOL(WINAPI* PFNCRYPTACQUIRECONTEXTA)(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
typedef BOOL(WINAPI* PFNCRYPTGENRANDOM)      (HCRYPTPROV, DWORD, BYTE*);
typedef BOOL(WINAPI* PFNCRYPTRELEASECONTEXT) (HCRYPTPROV, DWORD);

static PFNCRYPTACQUIRECONTEXTA s_pCryptAcquireContextA;
static PFNCRYPTGENRANDOM       s_pCryptGenRandom;
static PFNCRYPTRELEASECONTEXT  s_pCryptReleaseContext;
static int s_bShownWarningBoxOnMissingDependendies = 0;

void InitCryptContextStuffIfNeeded()
{
	if (s_bIsStuffInitted)
		return;
	
	s_pCryptAcquireContextA = NULL;
	s_pCryptGenRandom       = NULL;
	s_pCryptReleaseContext  = NULL;
	s_bIsStuffInitted = 1;
	
	HMODULE hmod = (HMODULE) GetModuleHandle("AdvApi32.dll");
	if (hmod)
	{
		s_pCryptAcquireContextA = (PFNCRYPTACQUIRECONTEXTA) GetProcAddress(hmod, "CryptAcquireContextA");
		s_pCryptGenRandom       = (PFNCRYPTGENRANDOM)       GetProcAddress(hmod, "CryptGenRandom");
		s_pCryptReleaseContext  = (PFNCRYPTRELEASECONTEXT)  GetProcAddress(hmod, "CryptReleaseContext");
	}
	
	if (!s_bShownWarningBoxOnMissingDependendies)
	{
		s_bShownWarningBoxOnMissingDependendies = 1;
		
		if (s_pCryptAcquireContextA &&
			s_pCryptGenRandom &&
			s_pCryptReleaseContext)
			return;
		
		MessageBoxA(
			NULL,
			"The OpenSSL library could not find some or all of the following APIs "
			"normally implemented by ADVAPI32 in your operating system:\n\n"
			"CryptAcquireContextA\n"
			"CryptGenRandom\n"
			"CryptReleaseContext\n\n"
			"It will be significantly easier to compromise your connection(s) using "
			"Discord Messenger. Ensure that your network isn't compromised or attacked "
			"via a man-in-the-middle.\n\n"
			"IMPORTANT: This warning should not show up if you are running anything "
			"newer than Windows 95 OSR2 (C revision)!  If it does, report it to "
			"iProgramInCpp at https://github.com/DiscordMessenger/openssl/issues.",
			"OpenSSL Security Warning",
			0
		);
	}
}

BOOL TEST_CryptAcquireContextA(
	HCRYPTPROV *phProv,
	LPCSTR pszContainer,
	LPCSTR pszProvider,
	DWORD dwProvType,
	DWORD dwFlags
)
{
	OutputDebugStringA("TEST_CryptAcquireContextA\n");
	InitCryptContextStuffIfNeeded();
	
	if (s_pCryptAcquireContextA)
		return s_pCryptAcquireContextA(phProv, pszContainer, pszProvider, dwProvType, dwFlags);
	
	// Just return true for now. It does nothing, and we'll give it some random data.
	// Perhaps seed the MSVCRT random for good measure.
	srand(GetTickCount());
	return TRUE;
}

BOOL TEST_CryptGenRandom(
	HCRYPTPROV hProv,
	DWORD dwLen,
	BYTE *pbBuffer
)
{
	OutputDebugStringA("TEST_CryptGenRandom\n");
	InitCryptContextStuffIfNeeded();
	
	if (s_pCryptGenRandom)
		return s_pCryptGenRandom(hProv, dwLen, pbBuffer);
	
	// Well we do need to fill it in with some random bytes, so here goes
	for (DWORD i = 0; i < dwLen; i++)
		pbBuffer[i] = (rand() & 0xFF);
	
	return TRUE;
}

BOOL TEST_CryptReleaseContext(
	HCRYPTPROV hProv,
	DWORD dwFlags
)
{
	OutputDebugStringA("TEST_CryptReleaseContext\n");
	InitCryptContextStuffIfNeeded();
	
	if (s_pCryptReleaseContext)
		return s_pCryptReleaseContext(hProv, dwFlags);
	
	// This does nothing, since the state of the hcryptprov didn't change
	return TRUE;
}

#else

#define TEST_CryptAcquireContextA CryptAcquireContextA
#define TEST_CryptGenRandom CryptGenRandom
#define TEST_CryptReleaseContext CryptReleaseContext

#endif

size_t ossl_pool_acquire_entropy(RAND_POOL *pool)
{
#ifndef USE_BCRYPTGENRANDOM
    HCRYPTPROV hProvider;
#endif
    unsigned char *buffer;
    size_t bytes_needed;
    size_t entropy_available = 0;

#ifdef OPENSSL_RAND_SEED_RDTSC
    entropy_available = ossl_prov_acquire_entropy_from_tsc(pool);
    if (entropy_available > 0)
        return entropy_available;
#endif

#ifdef OPENSSL_RAND_SEED_RDCPU
    entropy_available = ossl_prov_acquire_entropy_from_cpu(pool);
    if (entropy_available > 0)
        return entropy_available;
#endif

#ifdef USE_BCRYPTGENRANDOM
    bytes_needed = ossl_rand_pool_bytes_needed(pool, 1 /*entropy_factor*/);
    buffer = ossl_rand_pool_add_begin(pool, bytes_needed);
    if (buffer != NULL) {
        size_t bytes = 0;
        if (BCryptGenRandom(NULL, buffer, (ULONG)bytes_needed,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG)
            == STATUS_SUCCESS)
            bytes = bytes_needed;

        ossl_rand_pool_add_end(pool, bytes, 8 * bytes);
        entropy_available = ossl_rand_pool_entropy_available(pool);
    }
    if (entropy_available > 0)
        return entropy_available;
#else
    bytes_needed = ossl_rand_pool_bytes_needed(pool, 1 /*entropy_factor*/);
    buffer = ossl_rand_pool_add_begin(pool, bytes_needed);
    if (buffer != NULL) {
        size_t bytes = 0;
        /* poll the CryptoAPI PRNG */
        if (TEST_CryptAcquireContextA(&hProvider, NULL, NULL, PROV_RSA_FULL,
                                      CRYPT_VERIFYCONTEXT) != 0) {
            if (TEST_CryptGenRandom(hProvider, bytes_needed, buffer) != 0)
                bytes = bytes_needed;

            TEST_CryptReleaseContext(hProvider, 0);
        }

        ossl_rand_pool_add_end(pool, bytes, 8 * bytes);
        entropy_available = ossl_rand_pool_entropy_available(pool);
    }
    if (entropy_available > 0)
        return entropy_available;

    bytes_needed = ossl_rand_pool_bytes_needed(pool, 1 /*entropy_factor*/);
    buffer = ossl_rand_pool_add_begin(pool, bytes_needed);
    if (buffer != NULL) {
        size_t bytes = 0;
        /* poll the Pentium PRG with CryptoAPI */
        if (TEST_CryptAcquireContextA(&hProvider, NULL,
                                      INTEL_DEF_PROV, PROV_INTEL_SEC,
                                      CRYPT_VERIFYCONTEXT) != 0) {
            if (TEST_CryptGenRandom(hProvider, bytes_needed, buffer) != 0)
                bytes = bytes_needed;

            TEST_CryptReleaseContext(hProvider, 0);
        }
        ossl_rand_pool_add_end(pool, bytes, 8 * bytes);
        entropy_available = ossl_rand_pool_entropy_available(pool);
    }
    if (entropy_available > 0)
        return entropy_available;
#endif

    return ossl_rand_pool_entropy_available(pool);
}

int ossl_pool_add_nonce_data(RAND_POOL *pool)
{
    struct {
        DWORD pid;
        DWORD tid;
        FILETIME time;
    } data;

    /* Erase the entire structure including any padding */
    memset(&data, 0, sizeof(data));

    /*
     * Add process id, thread id, and a high resolution timestamp to
     * ensure that the nonce is unique with high probability for
     * different process instances.
     */
    data.pid = GetCurrentProcessId();
    data.tid = GetCurrentThreadId();
    GetSystemTimeAsFileTime(&data.time);

    return ossl_rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0);
}

int ossl_rand_pool_init(void)
{
    return 1;
}

void ossl_rand_pool_cleanup(void)
{
}

void ossl_rand_pool_keep_random_devices_open(int keep)
{
}

#endif
