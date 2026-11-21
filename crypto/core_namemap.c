/*
 * Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/namemap.h"
#include "internal/tsan_assist.h"
#include "internal/hashtable.h"
#include "internal/sizes.h"
#include "crypto/context.h"
#include "crypto/evp.h"

#define NAMEMAP_HT_BUCKETS 512

#define NAMEMAP_NAME_LEN 64
HT_START_KEY_DEFN(namenum_key)
HT_DEF_KEY_FIELD_CHAR_ARRAY(name, NAMEMAP_NAME_LEN)
HT_END_KEY_DEFN(NAMENUM_KEY)

/*-
 * The namemap itself
 * ==================
 */

typedef STACK_OF(OPENSSL_STRING) NAMES;

DEFINE_STACK_OF(NAMES)

struct ossl_namemap_st {
    /* Flags */
    unsigned int stored : 1; /* If 1, it's stored in a library context */

    HT *namenum_ht; /* Name->number mapping */

    CRYPTO_RWLOCK *lock;
    STACK_OF(NAMES) *numnames;

    TSAN_QUALIFIER int max_number; /* Current max number */
};

static void name_string_free(char *name)
{
    OPENSSL_free(name);
}

static void names_free(NAMES *n)
{
    sk_OPENSSL_STRING_pop_free(n, name_string_free);
}

/* OSSL_LIB_CTX_METHOD functions for a namemap stored in a library context */

void *ossl_stored_namemap_new(OSSL_LIB_CTX *libctx)
{
    OSSL_NAMEMAP *namemap = ossl_namemap_new(libctx);

    if (namemap != NULL)
        namemap->stored = 1;

    return namemap;
}

void ossl_stored_namemap_free(void *vnamemap)
{
    OSSL_NAMEMAP *namemap = vnamemap;

    if (namemap != NULL) {
        /* Pretend it isn't stored, or ossl_namemap_free() will do nothing */
        namemap->stored = 0;
        ossl_namemap_free(namemap);
    }
}

/*-
 * API functions
 * =============
 */

int ossl_namemap_empty(OSSL_NAMEMAP *namemap)
{
#ifdef TSAN_REQUIRES_LOCKING
    /* No TSAN support */
    int rv;

    if (namemap == NULL)
        return 1;

    if (!CRYPTO_THREAD_read_lock(namemap->lock))
        return -1;
    rv = namemap->max_number == 0;
    CRYPTO_THREAD_unlock(namemap->lock);
    return rv;
#else
    /* Have TSAN support */
    return namemap == NULL || tsan_load(&namemap->max_number) == 0;
#endif
}

/*
 * Call the callback for all names in the namemap with the given number.
 * A return value 1 means that the callback was called for all names. A
 * return value of 0 means that the callback was not called for any names.
 */
int ossl_namemap_doall_names(const OSSL_NAMEMAP *namemap, int number,
    void (*fn)(const char *name, void *data),
    void *data)
{
    int i;
    NAMES *names;

    if (namemap == NULL || number <= 0)
        return 0;

    /*
     * We duplicate the NAMES stack under a read lock. Subsequently we call
     * the user function, so that we're not holding the read lock when in user
     * code. This could lead to deadlocks.
     */
    if (!CRYPTO_THREAD_read_lock(namemap->lock))
        return 0;

    names = sk_NAMES_value(namemap->numnames, number - 1);
    if (names != NULL)
        names = sk_OPENSSL_STRING_dup(names);

    CRYPTO_THREAD_unlock(namemap->lock);

    if (names == NULL)
        return 0;

    for (i = 0; i < sk_OPENSSL_STRING_num(names); i++)
        fn(sk_OPENSSL_STRING_value(names, i), data);

    sk_OPENSSL_STRING_free(names);
    return i > 0;
}

int ossl_namemap_name2num(const OSSL_NAMEMAP *namemap, const char *name)
{
    if (name == NULL)
        return 0;
    return ossl_namemap_name2num_n(namemap, name, strlen(name));
}

int ossl_namemap_name2num_n(const OSSL_NAMEMAP *namemap,
    const char *name, size_t name_len)
{
    int number = 0;
    HT_VALUE *val;
    NAMENUM_KEY key;

#ifndef FIPS_MODULE
    if (namemap == NULL)
        namemap = ossl_namemap_stored(NULL);
#endif

    if (namemap == NULL)
        return 0;

    if (name_len > NAMEMAP_NAME_LEN)
        name_len = NAMEMAP_NAME_LEN;

    HT_INIT_RAW_KEY(&key);
    HT_COPY_RAW_KEY_CASE(TO_HT_KEY(&key), name, name_len);

    val = ossl_ht_get(namemap->namenum_ht, TO_HT_KEY(&key));

    if (val != NULL)
        /* We store a (small) int directly instead of a pointer to it. */
        number = (int)(intptr_t)val->value;

    return number;
}

const char *ossl_namemap_num2name(const OSSL_NAMEMAP *namemap, int number,
    int idx)
{
    NAMES *names;
    const char *ret = NULL;

    if (namemap == NULL || number <= 0)
        return NULL;

    if (!CRYPTO_THREAD_read_lock(namemap->lock))
        return NULL;

    names = sk_NAMES_value(namemap->numnames, number - 1);
    if (names != NULL)
        ret = sk_OPENSSL_STRING_value(names, idx);

    CRYPTO_THREAD_unlock(namemap->lock);

    return ret;
}

/* This function is not thread safe, the namemap must be locked */
static int numname_insert(OSSL_NAMEMAP *namemap, int number,
    const char *name)
{
    NAMES *names;
    char *tmpname;

    if (number > 0) {
        names = sk_NAMES_value(namemap->numnames, number - 1);
        if (!ossl_assert(names != NULL)) {
            /* cannot happen */
            return 0;
        }
    } else {
        /* a completely new entry */
        names = sk_OPENSSL_STRING_new_null();
        if (names == NULL)
            return 0;
    }

    if ((tmpname = OPENSSL_strdup(name)) == NULL)
        goto err;

    if (!sk_OPENSSL_STRING_push(names, tmpname))
        goto err;
    tmpname = NULL;

    if (number <= 0) {
        if (!sk_NAMES_push(namemap->numnames, names))
            goto err;
        number = sk_NAMES_num(namemap->numnames);
    }
    return number;

err:
    if (number <= 0)
        sk_OPENSSL_STRING_pop_free(names, name_string_free);
    OPENSSL_free(tmpname);
    return 0;
}

/* This function is not thread safe, the namemap must be locked */
static int namemap_add_name(OSSL_NAMEMAP *namemap, int number,
    const char *name)
{
    int ret;
    HT_VALUE val = { 0 };
    NAMENUM_KEY key;

    /* If it already exists, we don't add it */
    if ((ret = ossl_namemap_name2num(namemap, name)) != 0)
        return ret;

    if ((number = numname_insert(namemap, number, name)) == 0)
        return 0;

    /* Using tsan_store alone here is safe since we're under lock */
    tsan_store(&namemap->max_number, number);

    HT_INIT_RAW_KEY(&key);
    HT_COPY_RAW_KEY_CASE(TO_HT_KEY(&key), name, strlen(name));

    val.value = (void *)(intptr_t)number;
    ret = ossl_ht_insert(namemap->namenum_ht, TO_HT_KEY(&key), &val, NULL);
    if (ret <= 0) {
        /*
         * We either got an allocation failure (INTERNAL_ERROR), or
         * hit too many conflicts in the table (TOO_MANY_NAMES)
         */
        ERR_raise(ERR_LIB_CRYPTO, (ret < 0) ? CRYPTO_R_TOO_MANY_NAMES : ERR_R_INTERNAL_ERROR);
        return 0;
    }
    return number;
}

int ossl_namemap_add_name(OSSL_NAMEMAP *namemap, int number,
    const char *name)
{
    int tmp_number;

#ifndef FIPS_MODULE
    if (namemap == NULL)
        namemap = ossl_namemap_stored(NULL);
#endif

    if (name == NULL || *name == 0 || namemap == NULL)
        return 0;

    if (!CRYPTO_THREAD_write_lock(namemap->lock))
        return 0;
    tmp_number = namemap_add_name(namemap, number, name);
    CRYPTO_THREAD_unlock(namemap->lock);
    return tmp_number;
}

int ossl_namemap_add_names(OSSL_NAMEMAP *namemap, int number,
    const char *names, const char separator)
{
    char *tmp, *p, *q, *endp;

    /* Check that we have a namemap */
    if (!ossl_assert(namemap != NULL)) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if ((tmp = OPENSSL_strdup(names)) == NULL)
        return 0;

    if (!CRYPTO_THREAD_write_lock(namemap->lock)) {
        OPENSSL_free(tmp);
        return 0;
    }
    /*
     * Check that no name is an empty string, and that all names have at
     * most one numeric identity together.
     */
    for (p = tmp; *p != '\0'; p = q) {
        int this_number;
        size_t l;

        if ((q = strchr(p, separator)) == NULL) {
            l = strlen(p); /* offset to \0 */
            q = p + l;
        } else {
            l = q - p; /* offset to the next separator */
            *q++ = '\0';
        }

        if (*p == '\0') {
            ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_BAD_ALGORITHM_NAME);
            number = 0;
            goto end;
        }

        this_number = ossl_namemap_name2num(namemap, p);

        if (number == 0) {
            number = this_number;
        } else if (this_number != 0 && this_number != number) {
            ERR_raise_data(ERR_LIB_CRYPTO, CRYPTO_R_CONFLICTING_NAMES,
                "\"%s\" has an existing different identity %d (from \"%s\")",
                p, this_number, names);
            number = 0;
            goto end;
        }
    }
    endp = p;

    /* Now that we have checked, register all names */
    for (p = tmp; p < endp; p = q) {
        int this_number;

        q = p + strlen(p) + 1;

        this_number = namemap_add_name(namemap, number, p);
        if (number == 0) {
            number = this_number;
        } else if (this_number != number) {
            ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR,
                "Got number %d when expecting %d",
                this_number, number);
            number = 0;
            goto end;
        }
    }

end:
    CRYPTO_THREAD_unlock(namemap->lock);
    OPENSSL_free(tmp);
    return number;
}

/*-
 * Constructors / destructors
 * ==========================
 */

OSSL_NAMEMAP *ossl_namemap_stored(OSSL_LIB_CTX *libctx)
{
    OSSL_NAMEMAP *namemap = ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_NAMEMAP_INDEX);

    if (namemap == NULL)
        return NULL;

    return namemap;
}

OSSL_NAMEMAP *ossl_namemap_new(OSSL_LIB_CTX *libctx)
{
    OSSL_NAMEMAP *namemap;
    HT_CONFIG htconf = { NULL, NULL, NULL, NAMEMAP_HT_BUCKETS, 1, 1, 0 };

    htconf.ctx = libctx;

    if ((namemap = OPENSSL_zalloc(sizeof(*namemap))) == NULL)
        goto err;

    if ((namemap->lock = CRYPTO_THREAD_lock_new()) == NULL)
        goto err;

    if ((namemap->namenum_ht = ossl_ht_new(&htconf)) == NULL)
        goto err;

    if ((namemap->numnames = sk_NAMES_new_null()) == NULL)
        goto err;

    return namemap;

err:
    ossl_namemap_free(namemap);
    return NULL;
}

void ossl_namemap_free(OSSL_NAMEMAP *namemap)
{
    if (namemap == NULL || namemap->stored)
        return;

    sk_NAMES_pop_free(namemap->numnames, names_free);

    ossl_ht_free(namemap->namenum_ht);

    CRYPTO_THREAD_lock_free(namemap->lock);
    OPENSSL_free(namemap);
}
