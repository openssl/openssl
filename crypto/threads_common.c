/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
# include <string.h>

# include <internal/threads_common.h>
# include <internal/thread_once.h>

#define ARRAY_LEN(x) (sizeof(x)/sizeof((x)[0]))

typedef struct crypto_local_key_entry {
    CRYPTO_THREAD_LOCAL key;
    void (*cleanup)(void *);
} CRYPTO_LOCAL_KEY_ENTRY;

static void cleanup_err_state(void *ptr)
{
    CRYPTO_free(ptr, NULL, 0);
}

static CRYPTO_LOCAL_KEY_ENTRY key_table[] = {
    [CRYPTO_THREAD_DEF_CTX_KEY_ID] = {
            .cleanup = NULL,
        },
    [CRYPTO_THREAD_RCU_KEY_ID] = {
            .cleanup = NULL,
        },
    [CRYPTO_THREAD_ASYNC_JOB_CTX_KEY_ID] = {
            .cleanup = NULL,
        },
    [CRYPTO_THREAD_ASYNC_JOB_POOL_KEY_ID] = {
            .cleanup = NULL,
        },
    [CRYPTO_THREAD_ERR_KEY_ID] = {
            .cleanup = cleanup_err_state,
        },
    [CRYPTO_THREAD_INIT_CFG_KEY_ID] = {
            .cleanup = NULL,
        },

};

static size_t key_table_len = ARRAY_LEN(key_table);

static int init_keytable_once()
{
    size_t i;

    for (i = 0; i < key_table_len; i++) {
        if (!CRYPTO_THREAD_init_local(&key_table[i].key,
                                      key_table[i].cleanup))
            return 0;
    }
    return 1;
}

#ifdef FIPS_MODULE
# ifdef OPENSSL_SYS_UNIX
# include <pthread.h>

static int keytable_init_state = 0;
static pthread_once_t keytable_once = PTHREAD_ONCE_INIT;
static void pthread_init_keytable_once(void)
{
   keytable_init_state = init_keytable_once(); 
}

static int do_init_keytable_once()
{
    if (pthread_once(&keytable_once, pthread_init_keytable_once))
        keytable_init_state = 0;
    return keytable_init_state;
}

# elif OPENSSL_SYS_WIN
# define ONCE_UNINITED     0
# define ONCE_ININIT       1
# define ONCE_DONE         2
static volatile LONG win_once = ONCE_UNINITED;

static int do_init_keytable_once()
{
    LONG result;

    if (win_once == ONCE_DONE)
        return 1;

    do {
        result = InterlockedCompareExchange(&lock, ONCE_ININIT, ONCE_UNINITED);
        if (result == ONCE_UNINITED) {
            init_keytable_once();
            lock = ONCE_DONE;
            return 1;
        }
    } while (result == ONCE_ININIT);

    return (lock == ONCE_DONE);
}
# endif
#endif

#ifndef FIPS_MODULE
static CRYPTO_ONCE key_table_init = CRYPTO_ONCE_STATIC_INIT;

DEFINE_RUN_ONCE_STATIC(do_key_table_init)
{
    return init_keytable_once();
}
#endif

CRYPTO_THREAD_LOCAL*
CRYPTO_THREAD_get_key_entry(CRYPTO_THREAD_KEY_ENTRY_ID id)
{
#ifndef FIPS_MODULE
    if (!RUN_ONCE(&key_table_init, do_key_table_init))
        return NULL;
#else
    if (!do_init_keytable_once())
        return NULL;
#endif

    if (id >= CRYPTO_THREAD_KEY_ID_MAX)
        return NULL;

    return &key_table[id].key;
}
