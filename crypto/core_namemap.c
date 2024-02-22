/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/namemap.h"
#include <openssl/lhash.h>
#include "crypto/lhash.h"      /* ossl_lh_strcasehash */
#include "internal/hashtable.h"
#include "internal/tsan_assist.h"
#include "internal/sizes.h"
#include "crypto/context.h"

/*-
 * The namenum entry
 * =================
 */
typedef struct {
    char *name;
    int number;
} NAMENUM_ENTRY;

typedef struct numname_entry_st {
    NAMENUM_ENTRY *entry;
    struct numname_entry_st *next;
} NUMNAME_ENTRY;

/*
 * Defines our NAMENUM_ENTRY hashtable key
 */
HT_START_KEY_DEFN(namenum_key)
HT_DEF_KEY_FIELD_CHAR_ARRAY(name, 64)
HT_END_KEY_DEFN(NAMENUM_KEY)

HT_START_KEY_DEFN(numname_key)
HT_DEF_KEY_FIELD(number, int)
HT_END_KEY_DEFN(NUMNAME_KEY)

IMPLEMENT_HT_VALUE_TYPE_FNS(NAMENUM_ENTRY, nne, static)
IMPLEMENT_HT_VALUE_TYPE_FNS(NUMNAME_ENTRY, nne, static)

/*-
 * The namemap itself
 * ==================
 */

typedef void (*unlock_fn)(OSSL_NAMEMAP *);
typedef unlock_fn (*lock_fn)(OSSL_NAMEMAP *);
static unlock_fn do_setup_lock_real(OSSL_NAMEMAP *nm);

struct ossl_namemap_st {
    /* Flags */
    unsigned int stored:1; /* If 1, it's stored in a library context */

    HT *namenum;  /* Name->number mapping */

    CRYPTO_RWLOCK *setup_lock;
    CRYPTO_THREAD_ID setup_thread;
    lock_fn do_lock[2];
    int lock_idx;
    TSAN_QUALIFIER int max_number;     /* Current max number */
};

static void namenum_free(NAMENUM_ENTRY *n)
{
    if (n != NULL)
        OPENSSL_free(n->name);
    OPENSSL_free(n);
}

/* OSSL_LIB_CTX_METHOD functions for a namemap stored in a library context */

void *ossl_stored_namemap_new(OSSL_LIB_CTX *libctx)
{
    OSSL_NAMEMAP *namemap = ossl_namemap_new();

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

    rv = namemap->max_number == 0;
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
    NUMNAME_ENTRY *e = NULL;
    HT_VALUE *v = NULL;
    NUMNAME_KEY key;

    if (namemap == NULL)
        return 0;

    HT_INIT_KEY(&key);
    HT_SET_KEY_FIELD(&key, number, number);

    ossl_ht_read_lock(namemap->namenum);
    e = ossl_ht_nne_NUMNAME_ENTRY_get(namemap->namenum,
                                      TO_HT_KEY(&key), &v);
    ossl_ht_read_unlock(namemap->namenum);

    while (e != NULL) {
        fn(e->entry->name, data);
        e = e->next;
    }

    return 1;
}

static int namemap_name2num(const OSSL_NAMEMAP *namemap,
                            const char *name)
{
    NAMENUM_ENTRY *namenum_entry;
    HT_VALUE *v;
    NAMENUM_KEY key;
    int num;

    HT_INIT_KEY(&key);
    HT_SET_KEY_STRING_CASE(&key, name, name);

    ossl_ht_read_lock(namemap->namenum);
    v = ossl_ht_get(namemap->namenum, TO_HT_KEY(&key));
    if (v == NULL) {
        num = 0;
    } else {
        namenum_entry = ossl_ht_nne_NAMENUM_ENTRY_from_value(v);
        num = namenum_entry->number;
    }
    ossl_ht_read_unlock(namemap->namenum);
    return num;
}

int ossl_namemap_name2num(const OSSL_NAMEMAP *namemap, const char *name)
{
    int number;

#ifndef FIPS_MODULE
    if (namemap == NULL)
        namemap = ossl_namemap_stored(NULL);
#endif

    if (namemap == NULL)
        return 0;

    number = namemap_name2num(namemap, name);

    return number;
}

int ossl_namemap_name2num_n(const OSSL_NAMEMAP *namemap,
                            const char *name, size_t name_len)
{
    char *tmp;
    int ret;

    if (name == NULL || (tmp = OPENSSL_strndup(name, name_len)) == NULL)
        return 0;

    ret = ossl_namemap_name2num(namemap, tmp);
    OPENSSL_free(tmp);
    return ret;
}

const char *ossl_namemap_num2name(const OSSL_NAMEMAP *namemap, int number,
                                  size_t idx)
{
    NUMNAME_ENTRY *e;
    NUMNAME_KEY key;
    HT_VALUE *v = NULL;

    HT_INIT_KEY(&key);
    HT_SET_KEY_FIELD(&key, number, number);

    ossl_ht_read_lock(namemap->namenum);
    e = ossl_ht_nne_NUMNAME_ENTRY_get(namemap->namenum, TO_HT_KEY(&key), &v);
    ossl_ht_read_unlock(namemap->namenum);

    return e != NULL ? e->entry->name : NULL;
}

static int namemap_add_name(OSSL_NAMEMAP *namemap, int number,
                            const char *name)
{
    NAMENUM_ENTRY *namenum = NULL;
    NUMNAME_ENTRY *numname = NULL;
    NUMNAME_ENTRY *newnumname = NULL;
    HT_VALUE *v = NULL;
    int rc;
    int tmp_number;
    NAMENUM_KEY key;
    NUMNAME_KEY rkey;
    int retry_count = 0;

    HT_INIT_KEY(&key);
    HT_SET_KEY_STRING_CASE(&key, name, name);
    HT_INIT_KEY(&rkey);

    /* If it already exists, we don't add it */
    if ((tmp_number = namemap_name2num(namemap, name)) != 0)
        return tmp_number;

    if ((namenum = OPENSSL_zalloc(sizeof(*namenum))) == NULL)
        return 0;

    if ((newnumname = OPENSSL_zalloc(sizeof(*newnumname))) == NULL)
        goto err;

    if ((namenum->name = OPENSSL_strdup(name)) == NULL)
        goto err;

    /* The tsan_counter use here is safe since it uses atomics */
    namenum->number =
        number != 0 ? number : 1 + tsan_counter(&namemap->max_number);

    ossl_ht_write_lock(namemap->namenum);
    rc = ossl_ht_nne_NAMENUM_ENTRY_insert(namemap->namenum,
                                          TO_HT_KEY(&key), namenum, NULL);
    ossl_ht_write_unlock(namemap->namenum);
    if (rc == 0)
        goto err;

    HT_SET_KEY_FIELD(&rkey, number, namenum->number);

try_again:
    newnumname->entry = namenum;
    ossl_ht_read_lock(namemap->namenum);
    numname = ossl_ht_nne_NUMNAME_ENTRY_get(namemap->namenum, TO_HT_KEY(&rkey),
                                            &v);
    ossl_ht_read_unlock(namemap->namenum);
    if (numname == NULL) {
        if (retry_count > 0)
            goto err;
        ossl_ht_write_lock(namemap->namenum);
        rc = ossl_ht_nne_NUMNAME_ENTRY_insert(namemap->namenum, TO_HT_KEY(&rkey),
                                              newnumname, NULL);
        ossl_ht_write_unlock(namemap->namenum);
        if (rc == 0) {
            /*
             * Since we're not doing a replacement, it means another thread
             * raced in and added our entry for us, go back and try again
             * but only once, as not finding it on retry is an error
             */
            retry_count++;
            goto try_again;
        }
    } else {
        while (numname != NULL) {
            if (numname->next == NULL) {
                numname->next = newnumname;
                break;
            }
            numname = numname->next;
        }
    }
    return namenum->number;

 err:
    namenum_free(namenum);
    OPENSSL_free(newnumname);
    return 0;
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

    tmp_number = namemap_add_name(namemap, number, name);
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

    /*
     * Check that no name is an empty string, and that all names have at
     * most one numeric identity together.
     */
    for (p = tmp; *p != '\0'; p = q) {
        int this_number;
        size_t l;

        if ((q = strchr(p, separator)) == NULL) {
            l = strlen(p);       /* offset to \0 */
            q = p + l;
        } else {
            l = q - p;           /* offset to the next separator */
            *q++ = '\0';
        }

        if (*p == '\0') {
            ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_BAD_ALGORITHM_NAME);
            number = 0;
            goto end;
        }

        this_number = namemap_name2num(namemap, p);

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
    OPENSSL_free(tmp);
    return number;
}

/*-
 * Pre-population
 * ==============
 */

#ifndef FIPS_MODULE
#include <openssl/evp.h>

/* Creates an initial namemap with names found in the legacy method db */
static void get_legacy_evp_names(int base_nid, int nid, const char *pem_name,
                                 void *arg)
{
    int num = 0;
    ASN1_OBJECT *obj;

    if (base_nid != NID_undef) {
        num = ossl_namemap_add_name(arg, num, OBJ_nid2sn(base_nid));
        num = ossl_namemap_add_name(arg, num, OBJ_nid2ln(base_nid));
    }

    if (nid != NID_undef) {
        num = ossl_namemap_add_name(arg, num, OBJ_nid2sn(nid));
        num = ossl_namemap_add_name(arg, num, OBJ_nid2ln(nid));
        if ((obj = OBJ_nid2obj(nid)) != NULL) {
            char txtoid[OSSL_MAX_NAME_SIZE];

            if (OBJ_obj2txt(txtoid, sizeof(txtoid), obj, 1) > 0)
                num = ossl_namemap_add_name(arg, num, txtoid);
        }
    }
    if (pem_name != NULL)
        num = ossl_namemap_add_name(arg, num, pem_name);
}

static void get_legacy_cipher_names(const OBJ_NAME *on, void *arg)
{
    const EVP_CIPHER *cipher = (void *)OBJ_NAME_get(on->name, on->type);

    if (cipher != NULL)
        get_legacy_evp_names(NID_undef, EVP_CIPHER_get_type(cipher), NULL, arg);
}

static void get_legacy_md_names(const OBJ_NAME *on, void *arg)
{
    const EVP_MD *md = (void *)OBJ_NAME_get(on->name, on->type);

    if (md != NULL)
        get_legacy_evp_names(0, EVP_MD_get_type(md), NULL, arg);
}

static void get_legacy_pkey_meth_names(const EVP_PKEY_ASN1_METHOD *ameth,
                                       void *arg)
{
    int nid = 0, base_nid = 0, flags = 0;
    const char *pem_name = NULL;

    EVP_PKEY_asn1_get0_info(&nid, &base_nid, &flags, NULL, &pem_name, ameth);
    if (nid != NID_undef) {
        if ((flags & ASN1_PKEY_ALIAS) == 0) {
            switch (nid) {
            case EVP_PKEY_DHX:
                /* We know that the name "DHX" is used too */
                get_legacy_evp_names(0, nid, "DHX", arg);
                /* FALLTHRU */
            default:
                get_legacy_evp_names(0, nid, pem_name, arg);
            }
        } else {
            /*
             * Treat aliases carefully, some of them are undesirable, or
             * should not be treated as such for providers.
             */

            switch (nid) {
            case EVP_PKEY_SM2:
                /*
                 * SM2 is a separate keytype with providers, not an alias for
                 * EC.
                 */
                get_legacy_evp_names(0, nid, pem_name, arg);
                break;
            default:
                /* Use the short name of the base nid as the common reference */
                get_legacy_evp_names(base_nid, nid, pem_name, arg);
            }
        }
    }
}
#endif

/*-
 * Constructors / destructors
 * ==========================
 */

/*
 * This deserves some explination
 * with the new hashtable implementation, there was a desire
 * to operate locklessly, which is good.  However, ossl_namemap_stored
 * is potentially called from many threads at once, and the first caller
 * through this is meant to initalize the namemap table with all the cipher, md,
 * and pkey method names.  When this is run in parallel, now that the namemap
 * lock is gone, we occasionally get races, and so threads might do a lookup
 * while the table is getting populated, leading to negative lookups, etc, which
 * in turn results in various bad behavior (bad/early exits, erroneous errors,
 * etc).
 *
 * To combat that, what we need is for one and only one thread to do that
 * population, and for other threads to wait while it completes.  But adding a
 * lock here basically just re-introduces the lock we removed, which is...bad.
 *
 * So we have this scheme instead.
 *
 * What happens here is a stateful locking mechanism:
 * A call to ossl_namemap_stored, now calls namemap->lock_fn, which initailly
 * points to do_setup_lock_real, which takes the namemap write lock, and sets
 * the identity of the setup thread, if the setup_thread id is an inital value
 * of 0. This function returns an unlock function to the caller, which is called
 * on exit from ossl_namemap_stored.  do_setup_lock_real return
 * do_setup_unlock_real, which in turn updates the namemap lock_fn pointer to
 * point to do_setup_lock_nop, then unlocks the lock and returns
 *
 * Subsequent calls to the lock_fn pointer (after being updated to point to
 * do_setup_lock_nop return do_setup_unlock_nop, which just does a return
 *
 * In this way, any threads which attempt to call ossl_namemap_stored, will
 * block until the initial population is done on the context, but once the
 * context is populated, operation can continue locklessly
 *
 */

static void do_setup_unlock_nop(OSSL_NAMEMAP *nm)
{
    return;
}

static unlock_fn do_setup_lock_nop(OSSL_NAMEMAP *nm)
{
    return do_setup_unlock_nop;
}

static void do_setup_unlock_real(OSSL_NAMEMAP *nm)
{
    int toggle = 0;
    if (CRYPTO_THREAD_compare_id(nm->setup_thread,
                                 CRYPTO_THREAD_get_current_id())) {
        toggle = 1;
    }
    CRYPTO_THREAD_unlock(nm->setup_lock);

    if (toggle)
        CRYPTO_atomic_add(&nm->lock_idx, 1, &toggle, nm->setup_lock);
}

static unlock_fn do_setup_lock_real(OSSL_NAMEMAP *nm)
{
    if (!CRYPTO_THREAD_write_lock(nm->setup_lock))
        return NULL;
    if (CRYPTO_THREAD_compare_id(nm->setup_thread, (CRYPTO_THREAD_ID)0))
        nm->setup_thread = CRYPTO_THREAD_get_current_id();
    return do_setup_unlock_real;
}

OSSL_NAMEMAP *ossl_namemap_stored(OSSL_LIB_CTX *libctx)
{
#ifndef FIPS_MODULE
    int nms;
#endif
    void (*do_unlock)(OSSL_NAMEMAP *);
    int lock_idx;

    OSSL_NAMEMAP *namemap =
        ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_NAMEMAP_INDEX);

    if (namemap == NULL)
        return NULL;

    CRYPTO_atomic_load_int(&namemap->lock_idx, &lock_idx, &namemap->setup_lock);

    do_unlock = namemap->do_lock[lock_idx](namemap);
    if (do_unlock == NULL)
        return NULL;

#ifndef FIPS_MODULE
    nms = ossl_namemap_empty(namemap);
    if (nms < 0) {
        /*
         * Could not get lock to make the count, so maybe internal objects
         * weren't added. This seems safest.
         */
        do_unlock(namemap);
        return NULL;
    }
    if (nms == 1) {
        int i, end;

        /* Before pilfering, we make sure the legacy database is populated */
        OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS
                            | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);

        OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH,
                        get_legacy_cipher_names, namemap);
        OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH,
                        get_legacy_md_names, namemap);

        /* We also pilfer data from the legacy EVP_PKEY_ASN1_METHODs */
        for (i = 0, end = EVP_PKEY_asn1_get_count(); i < end; i++)
            get_legacy_pkey_meth_names(EVP_PKEY_asn1_get0(i), namemap);
    }
#endif

    do_unlock(namemap);
    return namemap;
}

static void namenum_ht_free(HT_VALUE *v)
{
    NAMENUM_ENTRY *e = NULL;
    NUMNAME_ENTRY *d = NULL;
    NUMNAME_ENTRY *dn = NULL;

    e = ossl_ht_nne_NAMENUM_ENTRY_from_value(v);
    if (e != NULL) {
        namenum_free(e);
    } else {
        d = ossl_ht_nne_NUMNAME_ENTRY_from_value(v);
        while (d != NULL) {
            dn = d->next;
            OPENSSL_free(d);
            d = dn;
        }
    }
    return;
}

OSSL_NAMEMAP *ossl_namemap_new(void)
{
    OSSL_NAMEMAP *namemap;

    /*
     * Hash table config
     * namenum_ht_free is our free fn
     * use the internal fnv1a hash
     * 1024 initial buckets
     * do lockless reads
     */
    HT_CONFIG ht_conf = {
        namenum_ht_free,
        NULL,
        1024,
    };

    if ((namemap = OPENSSL_zalloc(sizeof(*namemap))) == NULL)
        return NULL;

    namemap->setup_lock = CRYPTO_THREAD_lock_new();
    if (namemap->setup_lock == NULL) {
        OPENSSL_free(namemap);
        namemap = NULL;
        goto out;
    }

    namemap->namenum = ossl_ht_new(&ht_conf);
    if (namemap->namenum == NULL) {
        ossl_namemap_free(namemap);
        namemap = NULL;
    }

    namemap->do_lock[0] = do_setup_lock_real;
    namemap->do_lock[1] = do_setup_lock_nop;
    namemap->lock_idx = 0;
out:
    return namemap;
}

void ossl_namemap_free(OSSL_NAMEMAP *namemap)
{
    if (namemap == NULL || namemap->stored)
        return;

    ossl_ht_free(namemap->namenum);

    CRYPTO_THREAD_lock_free(namemap->setup_lock);

    OPENSSL_free(namemap);
}
