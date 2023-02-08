/*
 * Copyright 2016-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/types.h>
#include "simpledynamic.h"

typedef const SSL_METHOD * (*TLS_method_t)(void);
typedef SSL_CTX * (*SSL_CTX_new_t)(const SSL_METHOD *meth);
typedef void (*SSL_CTX_free_t)(SSL_CTX *);
typedef int (*OPENSSL_init_crypto_t)(uint64_t, void *);
typedef int (*OPENSSL_atexit_t)(void (*handler)(void));
typedef void (*OPENSSL_cleanup_t)(void);
typedef unsigned long (*ERR_get_error_t)(void);
typedef unsigned long (*OPENSSL_version_major_t)(void);
typedef unsigned long (*OPENSSL_version_minor_t)(void);
typedef unsigned long (*OPENSSL_version_patch_t)(void);

typedef enum test_types_en {
    CRYPTO_FIRST,
    SSL_FIRST,
    JUST_CRYPTO
} TEST_TYPE;

static TEST_TYPE test_type;
static const char *path_crypto;
static const char *path_ssl;
static const char *path_atexit;

#ifdef SD_INIT

static int atexit_handler_done = 0;

static void atexit_handler(void)
{
    FILE *atexit_file = fopen(path_atexit, "w");

    if (atexit_file == NULL)
        return;

    fprintf(atexit_file, "atexit() run\n");
    fclose(atexit_file);
    atexit_handler_done++;
}

static int test_lib(void)
{
    SD ssllib = SD_INIT;
    SD cryptolib = SD_INIT;
    SSL_CTX *ctx;
    union {
        void (*func)(void);
        SD_SYM sym;
    } symbols[6];
    TLS_method_t myTLS_method = NULL;
    SSL_CTX_new_t mySSL_CTX_new = NULL;
    SSL_CTX_free_t mySSL_CTX_free = NULL;
    ERR_get_error_t myERR_get_error = NULL;
    OPENSSL_version_major_t myOPENSSL_version_major = NULL;
    OPENSSL_version_minor_t myOPENSSL_version_minor = NULL;
    OPENSSL_version_patch_t myOPENSSL_version_patch = NULL;
    OPENSSL_atexit_t myOPENSSL_atexit = NULL;
    OPENSSL_cleanup_t myOPENSSL_cleanup = NULL;
    int result = 0;

    switch (test_type) {
    case JUST_CRYPTO:
    case CRYPTO_FIRST:
        if (!sd_load(path_crypto, &cryptolib, SD_SHLIB)) {
            fprintf(stderr, "Failed to load libcrypto\n");
            goto end;
        }
        if (test_type != CRYPTO_FIRST)
            break;
        /* Fall through */

    case SSL_FIRST:
        if (!sd_load(path_ssl, &ssllib, SD_SHLIB)) {
            fprintf(stderr, "Failed to load libssl\n");
            goto end;
        }
        if (test_type != SSL_FIRST)
            break;
        if (!sd_load(path_crypto, &cryptolib, SD_SHLIB)) {
            fprintf(stderr, "Failed to load libcrypto\n");
            goto end;
        }
        break;
    }

    if (ssllib != SD_INIT) {
        if (!sd_sym(ssllib, "TLS_method", &symbols[0].sym)
                || !sd_sym(ssllib, "SSL_CTX_new", &symbols[1].sym)
                || !sd_sym(ssllib, "SSL_CTX_free", &symbols[2].sym)) {
            fprintf(stderr, "Failed to load libssl symbols\n");
            goto end;
        }
        myTLS_method = (TLS_method_t)symbols[0].func;
        mySSL_CTX_new = (SSL_CTX_new_t)symbols[1].func;
        mySSL_CTX_free = (SSL_CTX_free_t)symbols[2].func;
    }

    if (!sd_sym(cryptolib, "ERR_get_error", &symbols[0].sym)
           || !sd_sym(cryptolib, "OPENSSL_version_major", &symbols[1].sym)
           || !sd_sym(cryptolib, "OPENSSL_version_minor", &symbols[2].sym)
           || !sd_sym(cryptolib, "OPENSSL_version_patch", &symbols[3].sym)
           || !sd_sym(cryptolib, "OPENSSL_atexit", &symbols[4].sym)
           || !sd_sym(cryptolib, "OPENSSL_cleanup", &symbols[5].sym)) {
        fprintf(stderr, "Failed to load libcrypto symbols\n");
        goto end;
    }
    myERR_get_error = (ERR_get_error_t)symbols[0].func;
    myOPENSSL_version_major = (OPENSSL_version_major_t)symbols[1].func;
    myOPENSSL_version_minor = (OPENSSL_version_minor_t)symbols[2].func;
    myOPENSSL_version_patch = (OPENSSL_version_patch_t)symbols[3].func;
    myOPENSSL_atexit = (OPENSSL_atexit_t)symbols[4].func;
    myOPENSSL_cleanup = (OPENSSL_cleanup_t)symbols[5].func;

    if (test_type != JUST_CRYPTO) {
        ctx = mySSL_CTX_new(myTLS_method());
        if (ctx == NULL) {
            fprintf(stderr, "Failed to create SSL_CTX\n");
            goto end;
        }
        mySSL_CTX_free(ctx);
    }

    if (myERR_get_error() != 0) {
        fprintf(stderr, "Unexpected ERR_get_error() response\n");
        goto end;
    }

    /* Library and header version should be identical in this test */
    if (myOPENSSL_version_major() != OPENSSL_VERSION_MAJOR
            || myOPENSSL_version_minor() != OPENSSL_VERSION_MINOR
            || myOPENSSL_version_patch() != OPENSSL_VERSION_PATCH) {
        fprintf(stderr, "Invalid library version number\n");
        goto end;
    }

    if (!myOPENSSL_atexit(atexit_handler)) {
        fprintf(stderr, "Failed to register atexit handler\n");
        goto end;
    }

    myOPENSSL_cleanup();
    if (!sd_close(cryptolib)) {
        fprintf(stderr, "Failed to close libcrypto\n");
        goto end;
    }
    cryptolib = SD_INIT;

    if (test_type == CRYPTO_FIRST || test_type == SSL_FIRST) {
        if (!sd_close(ssllib)) {
            fprintf(stderr, "Failed to close libssl\n");
            goto end;
        }
        ssllib = SD_INIT;
    }

    result = 1;
end:
    if (cryptolib != SD_INIT && myOPENSSL_cleanup != NULL)
        myOPENSSL_cleanup();
    if (cryptolib != SD_INIT)
        sd_close(cryptolib);
    if (ssllib != SD_INIT)
        sd_close(ssllib);
    return result;
}
#endif


/*
 * shlibloadtest should not use the normal test framework because we don't want
 * it to link against libcrypto (which the framework uses). The point of the
 * test is to check dynamic loading and unloading of libcrypto/libssl.
 */
int main(int argc, char *argv[])
{
    const char *p;

    if (argc != 5) {
        fprintf(stderr, "Incorrect number of arguments\n");
        return 1;
    }

    p = argv[1];

    if (strcmp(p, "-crypto_first") == 0) {
        test_type = CRYPTO_FIRST;
    } else if (strcmp(p, "-ssl_first") == 0) {
        test_type = SSL_FIRST;
    } else if (strcmp(p, "-just_crypto") == 0) {
        test_type = JUST_CRYPTO;
    } else {
        fprintf(stderr, "Unrecognised argument\n");
        return 1;
    }
    path_crypto = argv[2];
    path_ssl = argv[3];
    path_atexit = argv[4];
    if (path_crypto == NULL || path_ssl == NULL) {
        fprintf(stderr, "Invalid libcrypto/libssl path\n");
        return 1;
    }

#ifdef SD_INIT
    if (!test_lib())
        return 1;
#endif
    return 0;
}
