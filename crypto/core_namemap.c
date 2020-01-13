/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include "e_os.h"                /* strcasecmp */
#include "internal/namemap.h"
#include <opentls/lhash.h>
#include "crypto/lhash.h"      /* opentls_lh_strcasehash */

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

struct otls_namemap_st {
    /* Flags */
    unsigned int stored:1; /* If 1, it's stored in a library context */

    CRYPTO_RWLOCK *lock;
    LHASH_OF(NAMENUM_ENTRY) *namenum;  /* Name->number mapping */
    int max_number;                    /* Current max number */
};

/* LHASH callbacks */

static unsigned long namenum_hash(const NAMENUM_ENTRY *n)
{
    return opentls_lh_strcasehash(n->name);
}

static int namenum_cmp(const NAMENUM_ENTRY *a, const NAMENUM_ENTRY *b)
{
    return strcasecmp(a->name, b->name);
}

static void namenum_free(NAMENUM_ENTRY *n)
{
    if (n != NULL)
        OPENtls_free(n->name);
    OPENtls_free(n);
}

/* OPENtls_CTX_METHOD functions for a namemap stored in a library context */

static void *stored_namemap_new(OPENtls_CTX *libctx)
{
    Otls_NAMEMAP *namemap = otls_namemap_new();

    if (namemap != NULL)
        namemap->stored = 1;

    return namemap;
}

static void stored_namemap_free(void *vnamemap)
{
    Otls_NAMEMAP *namemap = vnamemap;

    if (namemap != NULL) {
        /* Pretend it isn't stored, or otls_namemap_free() will do nothing */
        namemap->stored = 0;
        otls_namemap_free(namemap);
    }
}

static const OPENtls_CTX_METHOD stored_namemap_method = {
    stored_namemap_new,
    stored_namemap_free,
};

/*-
 * API functions
 * =============
 */

Otls_NAMEMAP *otls_namemap_stored(OPENtls_CTX *libctx)
{
    return opentls_ctx_get_data(libctx, OPENtls_CTX_NAMEMAP_INDEX,
                                &stored_namemap_method);
}

Otls_NAMEMAP *otls_namemap_new(void)
{
    Otls_NAMEMAP *namemap;

    if ((namemap = OPENtls_zalloc(sizeof(*namemap))) != NULL
        && (namemap->lock = CRYPTO_THREAD_lock_new()) != NULL
        && (namemap->namenum =
            lh_NAMENUM_ENTRY_new(namenum_hash, namenum_cmp)) != NULL)
        return namemap;

    otls_namemap_free(namemap);
    return NULL;
}

void otls_namemap_free(Otls_NAMEMAP *namemap)
{
    if (namemap == NULL || namemap->stored)
        return;

    lh_NAMENUM_ENTRY_doall(namemap->namenum, namenum_free);
    lh_NAMENUM_ENTRY_free(namemap->namenum);

    CRYPTO_THREAD_lock_free(namemap->lock);
    OPENtls_free(namemap);
}

int otls_namemap_empty(Otls_NAMEMAP *namemap)
{
    int rv = 0;

    CRYPTO_THREAD_read_lock(namemap->lock);
    if (namemap->max_number == 0)
        rv = 1;
    CRYPTO_THREAD_unlock(namemap->lock);

    return rv;
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

void otls_namemap_doall_names(const Otls_NAMEMAP *namemap, int number,
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

int otls_namemap_name2num_n(const Otls_NAMEMAP *namemap,
                            const char *name, size_t name_len)
{
    NAMENUM_ENTRY *namenum_entry, namenum_tmpl;
    int number = 0;

#ifndef FIPS_MODE
    if (namemap == NULL)
        namemap = otls_namemap_stored(NULL);
#endif

    if (namemap == NULL)
        return 0;

    if ((namenum_tmpl.name = OPENtls_strndup(name, name_len)) == NULL)
        return 0;
    namenum_tmpl.number = 0;
    CRYPTO_THREAD_read_lock(namemap->lock);
    namenum_entry =
        lh_NAMENUM_ENTRY_retrieve(namemap->namenum, &namenum_tmpl);
    if (namenum_entry != NULL)
        number = namenum_entry->number;
    CRYPTO_THREAD_unlock(namemap->lock);
    OPENtls_free(namenum_tmpl.name);

    return number;
}

int otls_namemap_name2num(const Otls_NAMEMAP *namemap, const char *name)
{
    if (name == NULL)
        return 0;

    return otls_namemap_name2num_n(namemap, name, strlen(name));
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

const char *otls_namemap_num2name(const Otls_NAMEMAP *namemap, int number,
                                  size_t idx)
{
    struct num2name_data_st data;

    data.idx = idx;
    data.name = NULL;
    otls_namemap_doall_names(namemap, number, do_num2name, &data);
    return data.name;
}

int otls_namemap_add_name_n(Otls_NAMEMAP *namemap, int number,
                            const char *name, size_t name_len)
{
    NAMENUM_ENTRY *namenum = NULL;
    int tmp_number;

#ifndef FIPS_MODE
    if (namemap == NULL)
        namemap = otls_namemap_stored(NULL);
#endif

    if (name == NULL || name_len == 0 || namemap == NULL)
        return 0;

    if ((tmp_number = otls_namemap_name2num_n(namemap, name, name_len)) != 0)
        return tmp_number;       /* Pretend success */

    CRYPTO_THREAD_write_lock(namemap->lock);

    if ((namenum = OPENtls_zalloc(sizeof(*namenum))) == NULL
        || (namenum->name = OPENtls_strndup(name, name_len)) == NULL)
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

int otls_namemap_add_name(Otls_NAMEMAP *namemap, int number, const char *name)
{
    if (name == NULL)
        return 0;

    return otls_namemap_add_name_n(namemap, number, name, strlen(name));
}

int otls_namemap_add_names(Otls_NAMEMAP *namemap, int number,
                           const char *names, const char separator)
{
    const char *p, *q;
    size_t l;

    /* Check that we have a namemap */
    if (!otls_assert(namemap != NULL)) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /*
     * Check that no name is an empty string, and that all names have at
     * most one numeric identity together.
     */
    for (p = names; *p != '\0'; p = (q == NULL ? p + l : q + 1)) {
        int this_number;

        if ((q = strchr(p, separator)) == NULL)
            l = strlen(p);       /* offset to \0 */
        else
            l = q - p;           /* offset to the next separator */

        this_number = otls_namemap_name2num_n(namemap, p, l);

        if (*p == '\0' || *p == separator) {
            ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_BAD_ALGORITHM_NAME);
            return 0;
        }
        if (number == 0) {
            number = this_number;
        } else if (this_number != 0 && this_number != number) {
            ERR_raise_data(ERR_LIB_CRYPTO, CRYPTO_R_CONFLICTING_NAMES,
                           "\"%.*s\" has an existing different identity %d (from \"%s\")",
                           l, p, this_number, names);
            return 0;
        }
    }

    /* Now that we have checked, register all names */
    for (p = names; *p != '\0'; p = (q == NULL ? p + l : q + 1)) {
        int this_number;

        if ((q = strchr(p, separator)) == NULL)
            l = strlen(p);       /* offset to \0 */
        else
            l = q - p;           /* offset to the next separator */

        this_number = otls_namemap_add_name_n(namemap, number, p, l);
        if (number == 0) {
            number = this_number;
        } else if (this_number != number) {
            ERR_raise_data(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR,
                           "Got number %d when expecting %d",
                           this_number, number);
            return 0;
        }
    }

    return number;
}
