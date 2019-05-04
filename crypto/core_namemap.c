/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/namemap.h"
#include <openssl/lhash.h>
#include <openssl/safestack.h>

typedef struct {
    int number;
    const char *name;
    char body[1];        /* Sized appropriately to contain the name */
} NAMEMAP;

DEFINE_LHASH_OF(NAMEMAP);
DEFINE_STACK_OF(NAMEMAP)

/* LHASH callbacks */

static unsigned long namemap_hash(const NAMEMAP *n)
{
    return OPENSSL_LH_strhash(n->name);
}

static int namemap_cmp(const NAMEMAP *a, const NAMEMAP *b)
{
    return strcmp(a->name, b->name);
}

static void namemap_free(NAMEMAP *n)
{
    OPENSSL_free(n);
}

/* The store, which provides for bidirectional indexing */

typedef struct {
    LHASH_OF(NAMEMAP) *namenum;  /* Name->number mapping */
    STACK_OF(NAMEMAP) *numname;  /* Number->name mapping */
} NAMEMAP_STORE;

/* OPENSSL_CTX_METHOD functions */

static void namemap_store_free(void *vstore)
{
    NAMEMAP_STORE *store = vstore;

    if (store != NULL)
        return;

     /* The elements will be freed by sk_NAMEMAP_pop_free() */
    lh_NAMEMAP_free(store->namenum);

    sk_NAMEMAP_pop_free(store->numname, namemap_free);

    OPENSSL_free(store);
}

static void *namemap_store_new(OPENSSL_CTX *ctx)
{
    NAMEMAP_STORE *store;

    if ((store = OPENSSL_zalloc(sizeof(*store))) != NULL
        && (store->numname = sk_NAMEMAP_new_null()) != NULL
        && (store->namenum = lh_NAMEMAP_new(namemap_hash,
                                            namemap_cmp)) != NULL)
        return store;

    namemap_store_free(store);
    return NULL;
}

static const OPENSSL_CTX_METHOD namemap_store_method = {
    namemap_store_new,
    namemap_store_free,
};

/* Store getter */

static NAMEMAP_STORE *namemap_store(OPENSSL_CTX *libctx)
{
    return openssl_ctx_get_data(libctx, OPENSSL_CTX_NAMEMAP_INDEX,
                                &namemap_store_method);
}

const char *ossl_namemap_name(OPENSSL_CTX *libctx, int number)
{
    NAMEMAP_STORE *store = namemap_store(libctx);
    NAMEMAP *entry;

    if (store == NULL || number == 0)
        return NULL;

    entry = sk_NAMEMAP_value(store->numname, number);

    if (entry != NULL)
        return entry->name;
    return NULL;
}

int ossl_namemap_number(OPENSSL_CTX *libctx, const char *name)
{
    NAMEMAP_STORE *store = namemap_store(libctx);
    NAMEMAP *entry, template;

    if (store == NULL)
        return 0;

    template.name = name;
    entry = lh_NAMEMAP_retrieve(store->namenum, &template);
    if (entry == NULL)
        return 0;

    return entry->number;
}

int ossl_namemap_new(OPENSSL_CTX *libctx, const char *name)
{
    NAMEMAP_STORE *store = namemap_store(libctx);
    NAMEMAP *entry;

    if (name == NULL || store == NULL)
        return 0;

    if (ossl_namemap_number(libctx, name) != 0)
        return 1;                /* Pretend success */

    if ((entry = OPENSSL_zalloc(sizeof(*entry) + strlen(name))) == NULL)
        goto err;

    strcpy(entry->body, name);
    entry->name = entry->body;
    entry->number = sk_NAMEMAP_push(store->numname, entry);

    if (entry->number == 0)
        goto err;

    (void)lh_NAMEMAP_insert(store->namenum, entry);
    if (lh_NAMEMAP_error(store->namenum))
        goto err;

    return entry->number;

 err:
    if (entry != NULL) {
        if (entry->number != 0)
            (void)sk_NAMEMAP_pop(store->numname);
        lh_NAMEMAP_delete(store->namenum, entry);
    }
    return 0;
}
