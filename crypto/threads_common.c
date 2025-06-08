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

static CRYPTO_LOCAL_KEY_ENTRY *key_table_ptr = key_table;
static size_t key_table_len = ARRAY_LEN(key_table);

#ifndef FIPS_MODULE
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
#endif

    if (id >= key_table_len)
        return NULL;

    return &key_table_ptr[id].key;
}

void *get_thread_key_table(size_t *table_len)
{
    *table_len = key_table_len;
    return key_table;
}

#ifdef FIPS_MODULE
void set_thread_key_table(void *key_tbl, size_t table_len)
{
    key_table_ptr = key_tbl;
    key_table_len = table_len;
}
#endif

