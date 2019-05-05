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

/* The namemap entry */
typedef struct {
    int number;
    const char *name;
    char body[1];        /* Sized appropriately to contain the name */
} NAMEMAP_ENTRY;

DEFINE_LHASH_OF(NAMEMAP_ENTRY);
DEFINE_STACK_OF(NAMEMAP_ENTRY)

/* The namemap, which provides for bidirectional indexing */

struct ossl_namemap_st {
    /* Flags */
    unsigned int floating:1; /* If 0, it's stored in a library context */

    CRYPTO_RWLOCK *lock;
    LHASH_OF(NAMEMAP_ENTRY) *namenum;  /* Name->number mapping */
    STACK_OF(NAMEMAP_ENTRY) *numname;  /* Number->name mapping */
};

/* LHASH callbacks */

static unsigned long namemap_hash(const NAMEMAP_ENTRY *n)
{
    return OPENSSL_LH_strhash(n->name);
}

static int namemap_cmp(const NAMEMAP_ENTRY *a, const NAMEMAP_ENTRY *b)
{
    return strcmp(a->name, b->name);
}

static void namemap_free(NAMEMAP_ENTRY *n)
{
    OPENSSL_free(n);
}

/* OPENSSL_CTX_METHOD functions for a namemap stored in a library context */

static void *stored_namemap_new(OPENSSL_CTX *libctx)
{
    OSSL_NAMEMAP *namemap = ossl_namemap_new();

    if (namemap != NULL) {
        namemap->floating = 0;
    }

    return namemap;
}

static void stored_namemap_free(void *vnamemap)
{
    OSSL_NAMEMAP *namemap = vnamemap;

    /* Pretend it's floating, or ossl_namemap_free() will do nothing */
    namemap->floating = 1;
    ossl_namemap_free(namemap);
}

static const OPENSSL_CTX_METHOD stored_namemap_method = {
    stored_namemap_new,
    stored_namemap_free,
};

/* API functions */

OSSL_NAMEMAP *ossl_namemap_stored(OPENSSL_CTX *libctx)
{
    return openssl_ctx_get_data(libctx, OPENSSL_CTX_NAMEMAP_INDEX,
                                &stored_namemap_method);
}

OSSL_NAMEMAP *ossl_namemap_new(void)
{
    OSSL_NAMEMAP *namemap;

    if ((namemap = OPENSSL_zalloc(sizeof(*namemap))) != NULL
        && (namemap->lock = CRYPTO_THREAD_lock_new()) != NULL
        && (namemap->numname = sk_NAMEMAP_ENTRY_new_null()) != NULL
        && (namemap->namenum =
            lh_NAMEMAP_ENTRY_new(namemap_hash, namemap_cmp)) != NULL) {
        namemap->floating = 1;
        return namemap;
    }

    ossl_namemap_free(namemap);
    return NULL;
}

void ossl_namemap_free(OSSL_NAMEMAP *namemap)
{
    if (namemap == NULL || !namemap->floating)
        return;

     /* The elements will be freed by sk_NAMEMAP_ENTRY_pop_free() */
    lh_NAMEMAP_ENTRY_free(namemap->namenum);

    sk_NAMEMAP_ENTRY_pop_free(namemap->numname, namemap_free);

    CRYPTO_THREAD_lock_free(namemap->lock);
    OPENSSL_free(namemap);
}

/*
 * TODO(3.0) Make NULL to signify the default namemap, found in the default
 * library context.  The argument for wanting this is that there's no
 * general reason why the same string wouldn't result in the same number
 * within a unit...
 *
 * This isn't currently possible because of FIPS module constraints, so
 * we currently disable the code that would allow it.
 */

const char *ossl_namemap_name(OSSL_NAMEMAP *namemap, int number)
{
    NAMEMAP_ENTRY *entry;

#if 0                            /* TODO(3.0) */
    if (namemap == NULL)
        namemap = default_namemap();
#endif

    if (namemap == NULL || number == 0)
        return NULL;

    CRYPTO_THREAD_read_lock(namemap->lock);
    entry = sk_NAMEMAP_ENTRY_value(namemap->numname, number);
    CRYPTO_THREAD_unlock(namemap->lock);

    if (entry != NULL)
        return entry->name;
    return NULL;
}

int ossl_namemap_number(OSSL_NAMEMAP *namemap, const char *name)
{
    NAMEMAP_ENTRY *entry, template;

#if 0                            /* TODO(3.0) */
    if (namemap == NULL)
        namemap = default_namemap();
#endif

    if (namemap == NULL)
        return 0;

    template.name = name;
    CRYPTO_THREAD_read_lock(namemap->lock);
    entry = lh_NAMEMAP_ENTRY_retrieve(namemap->namenum, &template);
    CRYPTO_THREAD_unlock(namemap->lock);

    if (entry == NULL)
        return 0;

    return entry->number;
}

int ossl_namemap_add(OSSL_NAMEMAP *namemap, const char *name)
{
    NAMEMAP_ENTRY *entry;
    int number;

#if 0                            /* TODO(3.0) */
    if (namemap == NULL)
        namemap = default_namemap();
#endif

    if (name == NULL || namemap == NULL)
        return 0;

    if ((number = ossl_namemap_number(namemap, name)) != 0)
        return number;           /* Pretend success */

    if ((entry = OPENSSL_zalloc(sizeof(*entry) + strlen(name))) == NULL)
        goto err;

    strcpy(entry->body, name);
    entry->name = entry->body;

    CRYPTO_THREAD_write_lock(namemap->lock);

    entry->number = sk_NAMEMAP_ENTRY_push(namemap->numname, entry);

    if (entry->number == 0)
        goto err;

    (void)lh_NAMEMAP_ENTRY_insert(namemap->namenum, entry);
    if (lh_NAMEMAP_ENTRY_error(namemap->namenum))
        goto err;

    CRYPTO_THREAD_unlock(namemap->lock);

    return entry->number;

 err:
    if (entry != NULL) {
        if (entry->number != 0)
            (void)sk_NAMEMAP_ENTRY_pop(namemap->numname);
        lh_NAMEMAP_ENTRY_delete(namemap->namenum, entry);
        CRYPTO_THREAD_unlock(namemap->lock);
    }
    return 0;
}
