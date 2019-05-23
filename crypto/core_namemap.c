/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"                /* strcasecmp */
#include "internal/namemap.h"
#include <openssl/lhash.h>
#include "crypto/lhash.h"      /* openssl_lh_strcasehash */

/*-
 * The namenum entry
 * =================
 */
typedef struct {
    char *name;
    int number;
} NAMENUM_ENTRY;

DEFINE_LHASH_OF(NAMENUM_ENTRY);

/*-
 * The namemap itself
 * ==================
 */

struct ossl_namemap_st {
    /* Flags */
    unsigned int stored:1; /* If 1, it's stored in a library context */

    CRYPTO_RWLOCK *lock;
    LHASH_OF(NAMENUM_ENTRY) *namenum;  /* Name->number mapping */
    int max_number;                    /* Current max number */
};

/* LHASH callbacks */

static unsigned long namenum_hash(const NAMENUM_ENTRY *n)
{
    return openssl_lh_strcasehash(n->name);
}

static int namenum_cmp(const NAMENUM_ENTRY *a, const NAMENUM_ENTRY *b)
{
    return strcasecmp(a->name, b->name);
}

static void namenum_free(NAMENUM_ENTRY *n)
{
    if (n != NULL)
        OPENSSL_free(n->name);
    OPENSSL_free(n);
}

/* OPENSSL_CTX_METHOD functions for a namemap stored in a library context */

static void *stored_namemap_new(OPENSSL_CTX *libctx)
{
    OSSL_NAMEMAP *namemap = ossl_namemap_new();

    if (namemap != NULL)
        namemap->stored = 1;

    return namemap;
}

static void stored_namemap_free(void *vnamemap)
{
    OSSL_NAMEMAP *namemap = vnamemap;

    /* Pretend it isn't stored, or ossl_namemap_free() will do nothing */
    namemap->stored = 0;
    ossl_namemap_free(namemap);
}

static const OPENSSL_CTX_METHOD stored_namemap_method = {
    stored_namemap_new,
    stored_namemap_free,
};

/*-
 * API functions
 * =============
 */

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
        && (namemap->namenum =
            lh_NAMENUM_ENTRY_new(namenum_hash, namenum_cmp)) != NULL)
        return namemap;

    ossl_namemap_free(namemap);
    return NULL;
}

void ossl_namemap_free(OSSL_NAMEMAP *namemap)
{
    if (namemap == NULL || namemap->stored)
        return;

    lh_NAMENUM_ENTRY_doall(namemap->namenum, namenum_free);
    lh_NAMENUM_ENTRY_free(namemap->namenum);

    CRYPTO_THREAD_lock_free(namemap->lock);
    OPENSSL_free(namemap);
}

typedef struct doall_names_data_st {
    int number;
    void (*fn)(const char *name, void *data);
    void *data;
} DOALL_NAMES_DATA;

static void do_name(const NAMENUM_ENTRY *namenum, DOALL_NAMES_DATA *data)
{
    if (namenum->number == data->number)
        data->fn(namenum->name, data->data);
}

IMPLEMENT_LHASH_DOALL_ARG_CONST(NAMENUM_ENTRY, DOALL_NAMES_DATA);

void ossl_namemap_doall_names(const OSSL_NAMEMAP *namemap, int number,
                              void (*fn)(const char *name, void *data),
                              void *data)
{
    DOALL_NAMES_DATA cbdata;

    cbdata.number = number;
    cbdata.fn = fn;
    cbdata.data = data;
    CRYPTO_THREAD_read_lock(namemap->lock);
    lh_NAMENUM_ENTRY_doall_DOALL_NAMES_DATA(namemap->namenum, do_name,
                                            &cbdata);
    CRYPTO_THREAD_unlock(namemap->lock);
}

int ossl_namemap_name2num_n(const OSSL_NAMEMAP *namemap,
                            const char *name, size_t name_len)
{
    NAMENUM_ENTRY *namenum_entry, namenum_tmpl;
    int number = 0;

#ifndef FIPS_MODE
    if (namemap == NULL)
        namemap = ossl_namemap_stored(NULL);
#endif

    if (namemap == NULL)
        return 0;

    if ((namenum_tmpl.name = OPENSSL_strndup(name, name_len)) == NULL)
        return 0;
    namenum_tmpl.number = 0;
    CRYPTO_THREAD_read_lock(namemap->lock);
    namenum_entry =
        lh_NAMENUM_ENTRY_retrieve(namemap->namenum, &namenum_tmpl);
    if (namenum_entry != NULL)
        number = namenum_entry->number;
    CRYPTO_THREAD_unlock(namemap->lock);
    OPENSSL_free(namenum_tmpl.name);

    return number;
}

int ossl_namemap_name2num(const OSSL_NAMEMAP *namemap, const char *name)
{
    if (name == NULL)
        return 0;

    return ossl_namemap_name2num_n(namemap, name, strlen(name));
}

struct num2name_data_st {
    size_t idx;                  /* Countdown */
    const char *name;            /* Result */
};

static void do_num2name(const char *name, void *vdata)
{
    struct num2name_data_st *data = vdata;

    if (data->idx > 0)
        data->idx--;
    else if (data->name == NULL)
        data->name = name;
}

const char *ossl_namemap_num2name(const OSSL_NAMEMAP *namemap, int number,
                                  size_t idx)
{
    struct num2name_data_st data;

    data.idx = idx;
    data.name = NULL;
    ossl_namemap_doall_names(namemap, number, do_num2name, &data);
    return data.name;
}

int ossl_namemap_add_n(OSSL_NAMEMAP *namemap, int number,
                       const char *name, size_t name_len)
{
    NAMENUM_ENTRY *namenum = NULL;
    int tmp_number;

#ifndef FIPS_MODE
    if (namemap == NULL)
        namemap = ossl_namemap_stored(NULL);
#endif

    if (name == NULL || name_len == 0 || namemap == NULL)
        return 0;

    if ((tmp_number = ossl_namemap_name2num_n(namemap, name, name_len)) != 0)
        return tmp_number;       /* Pretend success */

    CRYPTO_THREAD_write_lock(namemap->lock);

    if ((namenum = OPENSSL_zalloc(sizeof(*namenum))) == NULL
        || (namenum->name = OPENSSL_strndup(name, name_len)) == NULL)
        goto err;

    namenum->number = tmp_number =
        number != 0 ? number : ++namemap->max_number;
    (void)lh_NAMENUM_ENTRY_insert(namemap->namenum, namenum);

    if (lh_NAMENUM_ENTRY_error(namemap->namenum))
        goto err;

    CRYPTO_THREAD_unlock(namemap->lock);

    return tmp_number;

 err:
    namenum_free(namenum);

    CRYPTO_THREAD_unlock(namemap->lock);
    return 0;
}

int ossl_namemap_add(OSSL_NAMEMAP *namemap, int number, const char *name)
{
    if (name == NULL)
        return 0;

    return ossl_namemap_add_n(namemap, number, name, strlen(name));
}
