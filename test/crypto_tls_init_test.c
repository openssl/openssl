/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Each invocation owns a fresh OpenSSL once-state. */
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "internal/e_os.h"
#include "crypto/cryptlib.h"

extern int __real_pthread_key_create(pthread_key_t *, void (*)(void *));
extern int __real_pthread_key_delete(pthread_key_t);
int __wrap_pthread_key_create(pthread_key_t *, void (*)(void *));
int __wrap_pthread_key_delete(pthread_key_t);
static unsigned int calls;
static unsigned int live_keys;
static unsigned int fail_at;
static int fail_master;
static int injected;
static pthread_key_t host_key;

int __wrap_pthread_key_create(pthread_key_t *key, void (*cleanup)(void *))
{
    ++calls;
    if ((fail_master && cleanup != NULL) || (fail_at != 0 && calls == fail_at)) {
        fail_master = 0;
        fail_at = calls;
        injected = 1;
        return EAGAIN; /* A failed allocation leaves the output untouched. */
    }
    {
        int ret = __real_pthread_key_create(key, cleanup);
        if (ret == 0)
            ++live_keys;
        return ret;
    }
}

int __wrap_pthread_key_delete(pthread_key_t key)
{
    int ret = __real_pthread_key_delete(key);
    if (ret == 0)
        --live_keys;
    return ret;
}

static int host_preserved(void)
{
    /* TLS values are opaque; OpenSSL must never dereference another owner's. */
    return pthread_getspecific(host_key) == (void *)1;
}

static void check_exit(void)
{
    /* OpenSSL exit callbacks must preserve unrelated host TLS. */
    if (!host_preserved() || __real_pthread_key_delete(host_key) != 0) {
        fprintf(stderr, "OpenSSL process-exit cleanup damaged host TLS\n");
        _Exit(1);
    }
}

static int master_key_failure(void)
{
    /* Base initialization must finish before failing the master key. */
    if (!OPENSSL_init_crypto(OPENSSL_INIT_BASE_ONLY, NULL))
        return 0;
    fail_master = 1;
    ERR_new();
    ERR_set_error(ERR_LIB_USER, 1, NULL);
    if (ERR_get_error() != 0 || !host_preserved())
        return 0;
    ERR_new();
    ERR_set_error(ERR_LIB_USER, 2, NULL);
    return ERR_get_error() == 0 && injected && calls == fail_at && host_preserved();
}

int main(int argc, char **argv)
{
    unsigned char bytes[16];
    int result;
    int explicit_cleanup;
    int master;
    alarm(15);
    if (argc != 3)
        return 2;
    master = strcmp(argv[1], "master") == 0;
    if (!master) {
        if (strlen(argv[1]) != 1 || argv[1][0] < '0' || argv[1][0] > '2')
            return 2;
        fail_at = (unsigned int)(argv[1][0] - '0');
    }
    explicit_cleanup = strcmp(argv[2], "cleanup") == 0;
    if ((!explicit_cleanup && strcmp(argv[2], "deferred") != 0) || (master && !explicit_cleanup))
        return 2;
    if (__real_pthread_key_create(&host_key, NULL) != 0 || pthread_setspecific(host_key, (void *)1) != 0 || atexit(check_exit) != 0)
        return 2;

    if (master) {
        if (!master_key_failure())
            return 1;
    } else {
        result = RAND_bytes(bytes, sizeof(bytes));
        printf("fail_at=%u calls=%u injected=%d RAND_bytes=%d cleanup=%s\n",
            fail_at, calls, injected, result, argv[2]);
        /* Target the destructor and configuration keys allocated by base init. */
        if (injected != (fail_at != 0) || result != (injected ? 0 : 1) || (injected && live_keys != 0) || !host_preserved())
            return 1;
        if (RAND_bytes(bytes, sizeof(bytes)) != (injected ? 0 : 1) || RAND_priv_bytes(bytes, sizeof(bytes)) != (injected ? 0 : 1) || !host_preserved())
            return 1;

        if (injected) {
            OSSL_LIB_CTX *context = OSSL_LIB_CTX_new();
            if (context != NULL) {
                OSSL_LIB_CTX_free(context);
                return 1;
            }
            if (OSSL_LIB_CTX_get0_global_default() != NULL || calls != fail_at || !host_preserved())
                return 1;
        }
    }

    if (explicit_cleanup) {
        OPENSSL_thread_stop();
        if (!host_preserved())
            return 1;
        OPENSSL_cleanup();
        ossl_cleanup_destructor();
        if (!host_preserved() || (injected && live_keys != 0))
            return 1;
    }
    if (!explicit_cleanup)
        OPENSSL_cleanup();
    return 0;
}
