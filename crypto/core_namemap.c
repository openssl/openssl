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

    if (namemap != NULL) {
        /* Pretend it isn't stored, or ossl_namemap_free() will do nothing */
        namemap->stored = 0;
        ossl_namemap_free(namemap);
    }
}

static const OPENSSL_CTX_METHOD stored_namemap_method = {
    stored_namemap_new,
    stored_namemap_free,
};

/*-
 * API functions
 * =============
 */

int ossl_namemap_empty(OSSL_NAMEMAP *namemap)
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

int ossl_namemap_add_name_n(OSSL_NAMEMAP *namemap, int number,
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

int ossl_namemap_add_name(OSSL_NAMEMAP *namemap, int number, const char *name)
{
    if (name == NULL)
        return 0;

    return ossl_namemap_add_name_n(namemap, number, name, strlen(name));
}

int ossl_namemap_add_names(OSSL_NAMEMAP *namemap, int number,
                           const char *names, const char separator)
{
    const char *p, *q;
    size_t l;

    /* Check that we have a namemap */
    if (!ossl_assert(namemap != NULL)) {
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

        this_number = ossl_namemap_name2num_n(namemap, p, l);

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

        this_number = ossl_namemap_add_name_n(namemap, number, p, l);
        if (number == 0) {
            number = this_number;
        } else if (this_number != number) {
            ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR,
                           "Got number %d when expecting %d",
                           this_number, number);
            return 0;
        }
    }

    return number;
}

/*-
 * Pre-population
 * ==============
 */

#ifndef FIPS_MODE
#include <openssl/evp.h>

/* Creates an initial namemap with names found in the legacy method db */
static void get_legacy_evp_names(const char *main_name, const char *alias,
                                 void *arg)
{
    int main_id = ossl_namemap_add_name(arg, 0, main_name);

    /*
     * We could check that the returned value is the same as main_id,
     * but since this is a void function, there's no sane way to report
     * the error.  The best we can do is trust ourselve to keep the legacy
     * method database conflict free.
     *
     * This registers any alias with the same number as the main name.
     * Should it be that the current |on| *has* the main name, this is
     * simply a no-op.
     */
    if (alias != NULL) {
        (void)ossl_namemap_add_name(arg, main_id, alias);
    }
}

static void get_legacy_cipher_names(const OBJ_NAME *on, void *arg)
{
    const EVP_CIPHER *cipher = (void *)OBJ_NAME_get(on->name, on->type);

    get_legacy_evp_names(EVP_CIPHER_name(cipher), on->name, arg);
}

static void get_legacy_md_names(const OBJ_NAME *on, void *arg)
{
    const EVP_MD *md = (void *)OBJ_NAME_get(on->name, on->type);
    /* We don't want the pkey_type names, so we need some extra care */
    int snid, lnid;

    snid = OBJ_sn2nid(on->name);
    lnid = OBJ_ln2nid(on->name);
    if (snid != EVP_MD_pkey_type(md) && lnid != EVP_MD_pkey_type(md))
        get_legacy_evp_names(EVP_MD_name(md), on->name, arg);
    else
        get_legacy_evp_names(EVP_MD_name(md), NULL, arg);
}
#endif

/*-
 * Constructors / destructors
 * ==========================
 */

OSSL_NAMEMAP *ossl_namemap_stored(OPENSSL_CTX *libctx)
{
    OSSL_NAMEMAP *namemap =
        openssl_ctx_get_data(libctx, OPENSSL_CTX_NAMEMAP_INDEX,
                             &stored_namemap_method);

#ifndef FIPS_MODE
    if (namemap != NULL && ossl_namemap_empty(namemap)) {
        /* Before pilfering, we make sure the legacy database is populated */
        OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS
                            | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);

        OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH,
                        get_legacy_cipher_names, namemap);
        OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH,
                        get_legacy_md_names, namemap);
    }
#endif

    return namemap;
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
