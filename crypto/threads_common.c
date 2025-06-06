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

static CRYPTO_LOCAL_KEY_ENTRY key_table[] = {
    [CRYPTO_THREAD_DEF_CTX_KEY_ID] = {
            .cleanup = NULL,
        },
    [CRYPTO_THREAD_RCU_KEY_ID] = {
            .cleanup = NULL,
        },
};

static size_t key_table_len = ARRAY_LEN(key_table);
static CRYPTO_ONCE key_table_init = CRYPTO_ONCE_STATIC_INIT;

DEFINE_RUN_ONCE_STATIC(do_key_table_init)
{
    size_t i;

    for (i = 0; i < key_table_len; i++) {
        if (!CRYPTO_THREAD_init_local(&key_table[i].key,
                                      key_table[i].cleanup))
            return 0;
    }
    return 1;
}

CRYPTO_THREAD_LOCAL*
CRYPTO_THREAD_get_key_entry(CRYPTO_THREAD_KEY_ENTRY_ID id)
{
    size_t i;

    if (!RUN_ONCE(&key_table_init, do_key_table_init))
        return NULL;

    if (id >= CRYPTO_THREAD_KEY_ID_MAX)
        return NULL;

    return &key_table[id].key;
}
