/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include <openssl/rand.h>
#include "crypto/rand_pool.h"
#include "crypto/rand.h"
#include "prov/seeding.h"

#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32)

# ifndef OPENSSL_RAND_SEED_OS
#  error "Unsupported seeding method configured; must be os"
# endif

# include <windows.h>
# include <wincrypt.h>
# include "internal/thread_once.h"

# ifndef STATUS_SUCCESS
#  define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
# endif

# ifndef GET_MODULE_HANDLE_EX_FLAG_PIN
# define GET_MODULE_HANDLE_EX_FLAG_PIN 0x00000001
# endif

# ifndef BCRYPT_USE_SYSTEM_PREFERRED_RNG
# define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
# endif

/* prototype of GetModuleHandleExA used to pin bcrypt.dll in memory */
typedef BOOL (WINAPI *GetModuleHandleExAFn)(
    DWORD        dwFlags,
    LPCSTR     lpModuleName,
    HMODULE*    phModule
);

/* prototype of BCryptGenRandom function from bcrypt.dll */
typedef long (WINAPI *BCryptGenRandomFn)(
    void* hAlgorithm,
    unsigned char* pbBuffer,
    unsigned long cbBuffer,
    unsigned long dwFlags
);

static BCryptGenRandomFn BCryptGenRandomPtr = NULL;
static CRYPTO_ONCE load_bcrypt_dll = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(do_load_bcrypt_dll)
{
    HMODULE hBCryptDll = NULL;
    char system32_path[MAX_PATH];
    GetModuleHandleExAFn GetModuleHandleExAPtr = NULL;
    
    /* We get pointer to GetModuleHandleExA dynamically in case it's not 
     * defined in the compiler's headers
     */
    GetModuleHandleExAPtr = 
        (GetModuleHandleExAFn) GetProcAddress (
            GetModuleHandleA ("kernel32.dll"), 
            "GetModuleHandleExA");
    if (GetModuleHandleExAPtr != NULL) {
        /* we load bcrypt.dll using absolute path to protect from
         * possible dll hijacking since bcrypt.dll is not part of 
         * the KnownDlls list protected by Windows from such attacks
         */
        if (GetSystemDirectoryA (system32_path, MAX_PATH) 
                && (strlen(system32_path) < (MAX_PATH - 11))) {
            /* we have enough room for "\bcrypt.dll" */
            strcat (system32_path, "\\bcrypt.dll");
        }
        else {
            strcpy (system32_path, "C:\\Windows\\System32\\bcrypt.dll");
        }
        /* Load bcrypt.dll if it is not already loaded and ensure that 
         * it remains loaded in memory to replicate previous behavior 
         * where it was linked against explicitely
         */
        if (!GetModuleHandleExAPtr (GET_MODULE_HANDLE_EX_FLAG_PIN, 
                                    system32_path, 
                                    &hBCryptDll)) {
            hBCryptDll = LoadLibraryA (system32_path);
            if (hBCryptDll != NULL) {
                GetModuleHandleExAPtr ( GET_MODULE_HANDLE_EX_FLAG_PIN, 
                                        system32_path, 
                                        &hBCryptDll);
            }
        }
    }

    if (hBCryptDll != NULL) {
        BCryptGenRandomPtr  = (BCryptGenRandomFn) 
            GetProcAddress (hBCryptDll, "BCryptGenRandom");
    }

    return 1;
}

/*
 * Intel hardware RNG CSP -- available from
 * http://developer.intel.com/design/security/rng/redist_license.htm
 */
# define PROV_INTEL_SEC 22
# define INTEL_DEF_PROV L"Intel Hardware Cryptographic Service Provider"

size_t ossl_pool_acquire_entropy(RAND_POOL *pool)
{
    HCRYPTPROV hProvider;
    unsigned char *buffer;
    size_t bytes_needed;
    size_t entropy_available = 0;

# ifdef OPENSSL_RAND_SEED_RDTSC
    entropy_available = ossl_prov_acquire_entropy_from_tsc(pool);
    if (entropy_available > 0)
        return entropy_available;
# endif

# ifdef OPENSSL_RAND_SEED_RDCPU
    entropy_available = ossl_prov_acquire_entropy_from_cpu(pool);
    if (entropy_available > 0)
        return entropy_available;
# endif

    if (RUN_ONCE(&load_bcrypt_dll, do_load_bcrypt_dll)) {
        if (BCryptGenRandomPtr != NULL) {
            bytes_needed = ossl_rand_pool_bytes_needed(pool, 1 /*entropy_factor*/);
            buffer = ossl_rand_pool_add_begin(pool, bytes_needed);
            if (buffer != NULL) {
                size_t bytes = 0;
                if (BCryptGenRandomPtr(NULL, buffer, bytes_needed,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) == STATUS_SUCCESS)
                    bytes = bytes_needed;

                ossl_rand_pool_add_end(pool, bytes, 8 * bytes);
                entropy_available = ossl_rand_pool_entropy_available(pool);
            }
            if (entropy_available > 0)
                return entropy_available;
        }
    }

    bytes_needed = ossl_rand_pool_bytes_needed(pool, 1 /*entropy_factor*/);
    buffer = ossl_rand_pool_add_begin(pool, bytes_needed);
    if (buffer != NULL) {
        size_t bytes = 0;
        /* poll the CryptoAPI PRNG */
        if (CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_FULL,
                                 CRYPT_VERIFYCONTEXT | CRYPT_SILENT) != 0) {
            if (CryptGenRandom(hProvider, bytes_needed, buffer) != 0)
                bytes = bytes_needed;

            CryptReleaseContext(hProvider, 0);
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
        if (CryptAcquireContextW(&hProvider, NULL,
                                 INTEL_DEF_PROV, PROV_INTEL_SEC,
                                 CRYPT_VERIFYCONTEXT | CRYPT_SILENT) != 0) {
            if (CryptGenRandom(hProvider, bytes_needed, buffer) != 0)
                bytes = bytes_needed;

            CryptReleaseContext(hProvider, 0);
        }
        ossl_rand_pool_add_end(pool, bytes, 8 * bytes);
        entropy_available = ossl_rand_pool_entropy_available(pool);
    }
    if (entropy_available > 0)
        return entropy_available;

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
