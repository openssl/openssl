/*
 * Copyright 2016-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>
#include "testutil.h"

typedef const SSL_METHOD * (*TLS_method_t)(void);
typedef SSL_CTX * (*SSL_CTX_new_t)(const SSL_METHOD *meth);
typedef void (*SSL_CTX_free_t)(SSL_CTX *);
typedef unsigned long (*ERR_get_error_t)(void);
typedef unsigned long (*OpenSSL_version_num_t)(void);

typedef enum test_types_en {
    CRYPTO_FIRST,
    SSL_FIRST,
    JUST_CRYPTO
} TEST_TYPE;

static TEST_TYPE test_type;
static const char *path_crypto;
static const char *path_ssl;

#ifdef DSO_DLFCN

# include <dlfcn.h>

# define SHLIB_INIT NULL

typedef void *SHLIB;
typedef void *SHLIB_SYM;

static int shlib_load(const char *filename, SHLIB *lib)
{
    *lib = dlopen(filename, RTLD_GLOBAL | RTLD_LAZY);
    return *lib == NULL ? 0 : 1;
}

static int shlib_sym(SHLIB lib, const char *symname, SHLIB_SYM *sym)
{
    *sym = dlsym(lib, symname);
    return *sym != NULL;
}

# ifdef OPENSSL_USE_NODELETE
static int shlib_close(SHLIB lib)
{
    return dlclose(lib) != 0 ? 0 : 1;
}
# endif
#endif

#ifdef DSO_WIN32

# include <windows.h>

# define SHLIB_INIT 0

typedef HINSTANCE SHLIB;
typedef void *SHLIB_SYM;

static int shlib_load(const char *filename, SHLIB *lib)
{
    *lib = LoadLibraryA(filename);
    return *lib == NULL ? 0 : 1;
}

static int shlib_sym(SHLIB lib, const char *symname, SHLIB_SYM *sym)
{
    *sym = (SHLIB_SYM)GetProcAddress(lib, symname);
    return *sym != NULL;
}

# ifdef OPENSSL_USE_NODELETE
static int shlib_close(SHLIB lib)
{
    return FreeLibrary(lib) == 0 ? 0 : 1;
}
# endif
#endif


#if defined(DSO_DLFCN) || defined(DSO_WIN32)

static int test_lib(void)
{
    SHLIB ssllib = SHLIB_INIT;
    SHLIB cryptolib = SHLIB_INIT;
    SSL_CTX *ctx;
    union {
        void (*func)(void);
        SHLIB_SYM sym;
    } symbols[3];
    TLS_method_t myTLS_method;
    SSL_CTX_new_t mySSL_CTX_new;
    SSL_CTX_free_t mySSL_CTX_free;
    ERR_get_error_t myERR_get_error;
    OpenSSL_version_num_t myOpenSSL_version_num;
    int result = 0;

    switch (test_type) {
    case JUST_CRYPTO:
        if (!TEST_true(shlib_load(path_crypto, &cryptolib)))
            goto end;
        break;
    case CRYPTO_FIRST:
        if (!TEST_true(shlib_load(path_crypto, &cryptolib))
                || !TEST_true(shlib_load(path_ssl, &ssllib)))
            goto end;
        break;
    case SSL_FIRST:
        if (!TEST_true(shlib_load(path_ssl, &ssllib))
                || !TEST_true(shlib_load(path_crypto, &cryptolib)))
            goto end;
        break;
    }

    if (test_type != JUST_CRYPTO) {
        if (!TEST_true(shlib_sym(ssllib, "TLS_method", &symbols[0].sym))
                || !TEST_true(shlib_sym(ssllib, "SSL_CTX_new", &symbols[1].sym))
                || !TEST_true(shlib_sym(ssllib, "SSL_CTX_free", &symbols[2].sym)))
            goto end;
        myTLS_method = (TLS_method_t)symbols[0].func;
        mySSL_CTX_new = (SSL_CTX_new_t)symbols[1].func;
        mySSL_CTX_free = (SSL_CTX_free_t)symbols[2].func;
        if (!TEST_ptr(ctx = mySSL_CTX_new(myTLS_method())))
            goto end;
        mySSL_CTX_free(ctx);
    }

    if (!TEST_true(shlib_sym(cryptolib, "ERR_get_error", &symbols[0].sym))
            || !TEST_true(shlib_sym(cryptolib, "OpenSSL_version_num",
                                    &symbols[1].sym)))
        goto end;
    myERR_get_error = (ERR_get_error_t)symbols[0].func;
    if (!TEST_int_eq(myERR_get_error(), 0))
        goto end;
    myOpenSSL_version_num = (OpenSSL_version_num_t)symbols[1].func;
    if (!TEST_int_eq(myOpenSSL_version_num(), OPENSSL_VERSION_NUMBER))
        goto end;

#ifdef OPENSSL_USE_NODELETE
    switch (test_type) {
    case JUST_CRYPTO:
        if (!TEST_true(shlib_close(cryptolib)))
            goto end;
        break;
    case CRYPTO_FIRST:
        if (!TEST_true(shlib_close(cryptolib))
                || !TEST_true(shlib_close(ssllib)))
            goto end;
        break;
    case SSL_FIRST:
        if (!TEST_true(shlib_close(ssllib))
                || !TEST_true(shlib_close(cryptolib)))
            goto end;
        break;
    }
#endif

    result = 1;
end:
    return result;
}
#endif


int test_main(int argc, char **argv)
{
    if (argc != 4) {
        TEST_error("Unexpected number of arguments");
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "-crypto_first") == 0) {
        test_type = CRYPTO_FIRST;
    } else if (strcmp(argv[1], "-ssl_first") == 0) {
        test_type = SSL_FIRST;
    } else if (strcmp(argv[1], "-just_crypto") == 0) {
        test_type = JUST_CRYPTO;
    } else {
        TEST_error("Unrecognised argument");
        return EXIT_FAILURE;
    }
    path_crypto = argv[2];
    path_ssl = argv[3];

#if defined(DSO_DLFCN) || defined(DSO_WIN32)
    ADD_TEST(test_lib);
#endif
    return run_tests(argv[0]);
}
