/*
 * Copyright 2019-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <stdio.h>
#include <openssl/types.h>
#include <openssl/evp.h>
#include <openssl/core.h>
#include <openssl/kdf.h>
#include "internal/cryptlib.h"
#include "internal/thread_once.h"
#include "internal/property.h"
#include "internal/core.h"
#include "internal/provider.h"
#include "internal/namemap.h"
#include "internal/hashtable.h"
#include "internal/threads_common.h"
#include "internal/tsan_assist.h"
#include "crypto/decoder.h"
#include "crypto/evp.h" /* evp_local.h needs it */
#include "crypto/cryptlib.h"
#include "evp_local.h"

typedef struct evp_cache_key {
    HT_KEY key_header;
} EVP_CACHE_KEY;

typedef struct evp_thread_cache {
    int flush_generation;
    HT *cache;
} EVP_THREAD_CACHE;

static TSAN_QUALIFIER int flush_generation = 0;

IMPLEMENT_HT_VALUE_TYPE_FNS(EVP_MD, evpcache, static)
IMPLEMENT_HT_VALUE_TYPE_FNS(EVP_CIPHER, evpcache, static)
IMPLEMENT_HT_VALUE_TYPE_FNS(EVP_MAC, evpcache, static)
IMPLEMENT_HT_VALUE_TYPE_FNS(EVP_KDF, evpcache, static)
IMPLEMENT_HT_VALUE_TYPE_FNS(EVP_RAND, evpcache, static)
IMPLEMENT_HT_VALUE_TYPE_FNS(EVP_KEYMGMT, evpcache, static)
IMPLEMENT_HT_VALUE_TYPE_FNS(EVP_KEYEXCH, evpcache, static)
IMPLEMENT_HT_VALUE_TYPE_FNS(EVP_SIGNATURE, evpcache, static)
IMPLEMENT_HT_VALUE_TYPE_FNS(EVP_ASYM_CIPHER, evpcache, static)
IMPLEMENT_HT_VALUE_TYPE_FNS(EVP_KEM, evpcache, static)
IMPLEMENT_HT_VALUE_TYPE_FNS(EVP_SKEYMGMT, evpcache, static)

#define NAME_SEPARATOR ':'

/* Data to be passed through ossl_method_construct() */
struct evp_method_data_st {
    OSSL_LIB_CTX *libctx;
    int operation_id; /* For get_evp_method_from_store() */
    int name_id; /* For get_evp_method_from_store() */
    const char *names; /* For get_evp_method_from_store() */
    const char *propquery; /* For get_evp_method_from_store() */

    OSSL_METHOD_STORE *tmp_store; /* For get_tmp_evp_method_store() */

    unsigned int flag_construct_error_occurred : 1;

    void *(*method_from_algorithm)(int name_id, const OSSL_ALGORITHM *,
        OSSL_PROVIDER *);
    int (*refcnt_up_method)(void *method);
    void (*destruct_method)(void *method);
};

/*
 * Generic routines to fetch / create EVP methods with ossl_method_construct()
 */
static void *get_tmp_evp_method_store(void *data)
{
    struct evp_method_data_st *methdata = data;

    if (methdata->tmp_store == NULL) {
        methdata->tmp_store = ossl_method_store_new(methdata->libctx);
        OSSL_TRACE1(QUERY, "Allocating a new tmp_store %p\n", (void *)methdata->tmp_store);
    } else {
        OSSL_TRACE1(QUERY, "Using the existing tmp_store %p\n", (void *)methdata->tmp_store);
    }
    return methdata->tmp_store;
}

static void dealloc_tmp_evp_method_store(void *store)
{
    OSSL_TRACE1(QUERY, "Deallocating the tmp_store %p\n", store);
    if (store != NULL)
        ossl_method_store_free(store);
}

static OSSL_METHOD_STORE *get_evp_method_store(OSSL_LIB_CTX *libctx)
{
    return ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX);
}

static int reserve_evp_method_store(void *store, void *data)
{
    struct evp_method_data_st *methdata = data;

    if (store == NULL
        && (store = get_evp_method_store(methdata->libctx)) == NULL)
        return 0;

    return ossl_method_lock_store(store);
}

static int unreserve_evp_method_store(void *store, void *data)
{
    struct evp_method_data_st *methdata = data;

    if (store == NULL
        && (store = get_evp_method_store(methdata->libctx)) == NULL)
        return 0;

    return ossl_method_unlock_store(store);
}

/*
 * To identify the method in the EVP method store, we mix the name identity
 * with the operation identity, under the assumption that we don't have more
 * than 2^23 names or more than 2^8 operation types.
 *
 * The resulting identity is a 31-bit integer, composed like this:
 *
 * +---------23 bits--------+-8 bits-+
 * |      name identity     | op id  |
 * +------------------------+--------+
 *
 * We limit this composite number to 31 bits, thus leaving the top uint32_t
 * bit always zero, to avoid negative sign extension when downshifting after
 * this number happens to be passed to an int (which happens as soon as it's
 * passed to ossl_method_store_cache_set(), and it's in that form that it
 * gets passed along to filter_on_operation_id(), defined further down.
 */
#define METHOD_ID_OPERATION_MASK 0x000000FF
#define METHOD_ID_OPERATION_MAX ((1 << 8) - 1)
#define METHOD_ID_NAME_MASK 0x7FFFFF00
#define METHOD_ID_NAME_OFFSET 8
#define METHOD_ID_NAME_MAX ((1 << 23) - 1)
static uint32_t evp_method_id(int name_id, unsigned int operation_id)
{
    if (!ossl_assert(name_id > 0 && name_id <= METHOD_ID_NAME_MAX)
        || !ossl_assert(operation_id > 0
            && operation_id <= METHOD_ID_OPERATION_MAX))
        return 0;
    return (((name_id << METHOD_ID_NAME_OFFSET) & METHOD_ID_NAME_MASK)
        | (operation_id & METHOD_ID_OPERATION_MASK));
}

static void *get_evp_method_from_store(void *store, const OSSL_PROVIDER **prov,
    void *data)
{
    struct evp_method_data_st *methdata = data;
    void *method = NULL;
    int name_id;
    uint32_t meth_id;

    /*
     * get_evp_method_from_store() is only called to try and get the method
     * that evp_generic_fetch() is asking for, and the operation id as well
     * as the name or name id are passed via methdata.
     */
    if ((name_id = methdata->name_id) == 0 && methdata->names != NULL) {
        OSSL_NAMEMAP *namemap = ossl_namemap_stored(methdata->libctx);
        const char *names = methdata->names;
        const char *q = strchr(names, NAME_SEPARATOR);
        size_t l = (q == NULL ? strlen(names) : (size_t)(q - names));

        if (namemap == 0)
            return NULL;
        name_id = ossl_namemap_name2num_n(namemap, names, l);
    }

    if (name_id == 0
        || (meth_id = evp_method_id(name_id, methdata->operation_id)) == 0)
        return NULL;

    if (store == NULL
        && (store = get_evp_method_store(methdata->libctx)) == NULL)
        return NULL;

    if (!ossl_method_store_fetch(store, meth_id, methdata->propquery, prov,
            &method))
        return NULL;
    return method;
}

static int put_evp_method_in_store(void *store, void *method,
    const OSSL_PROVIDER *prov,
    const char *names, const char *propdef,
    void *data)
{
    struct evp_method_data_st *methdata = data;
    OSSL_NAMEMAP *namemap;
    int name_id;
    uint32_t meth_id;
    size_t l = 0;

    /*
     * put_evp_method_in_store() is only called with an EVP method that was
     * successfully created by construct_method() below, which means that
     * all the names should already be stored in the namemap with the same
     * numeric identity, so just use the first to get that identity.
     */
    if (names != NULL) {
        const char *q = strchr(names, NAME_SEPARATOR);

        l = (q == NULL ? strlen(names) : (size_t)(q - names));
    }

    if ((namemap = ossl_namemap_stored(methdata->libctx)) == NULL
        || (name_id = ossl_namemap_name2num_n(namemap, names, l)) == 0
        || (meth_id = evp_method_id(name_id, methdata->operation_id)) == 0)
        return 0;

    OSSL_TRACE1(QUERY, "put_evp_method_in_store: original store: %p\n", store);
    if (store == NULL
        && (store = get_evp_method_store(methdata->libctx)) == NULL)
        return 0;

    OSSL_TRACE5(QUERY,
        "put_evp_method_in_store: "
        "store: %p, names: %s, operation_id %d, method_id: %d, properties: %s\n",
        store, names, methdata->operation_id, meth_id, propdef ? propdef : "<null>");
    return ossl_method_store_add(store, prov, meth_id, propdef, method,
        methdata->refcnt_up_method,
        methdata->destruct_method);
}

/*
 * The core fetching functionality passes the name of the implementation.
 * This function is responsible to getting an identity number for it.
 */
static void *construct_evp_method(const OSSL_ALGORITHM *algodef,
    OSSL_PROVIDER *prov, void *data)
{
    /*
     * This function is only called if get_evp_method_from_store() returned
     * NULL, so it's safe to say that of all the spots to create a new
     * namemap entry, this is it.  Should the name already exist there, we
     * know that ossl_namemap_add_name() will return its corresponding
     * number.
     */
    struct evp_method_data_st *methdata = data;
    OSSL_LIB_CTX *libctx = ossl_provider_libctx(prov);
    OSSL_NAMEMAP *namemap = ossl_namemap_stored(libctx);
    const char *names = algodef->algorithm_names;
    int name_id = ossl_namemap_add_names(namemap, 0, names, NAME_SEPARATOR);
    void *method;

    if (name_id == 0)
        return NULL;

    method = methdata->method_from_algorithm(name_id, algodef, prov);

    /*
     * Flag to indicate that there was actual construction errors.  This
     * helps inner_evp_generic_fetch() determine what error it should
     * record on inaccessible algorithms.
     */
    if (method == NULL)
        methdata->flag_construct_error_occurred = 1;

    return method;
}

static void destruct_evp_method(void *method, void *data)
{
    struct evp_method_data_st *methdata = data;

    methdata->destruct_method(method);
}

static void *
inner_evp_generic_fetch(struct evp_method_data_st *methdata,
    OSSL_PROVIDER *prov, int operation_id,
    const char *name, ossl_unused const char *properties,
    void *(*new_method)(int name_id,
        const OSSL_ALGORITHM *algodef,
        OSSL_PROVIDER *prov),
    int (*up_ref_method)(void *),
    void (*free_method)(void *))
{
    OSSL_METHOD_STORE *store = get_evp_method_store(methdata->libctx);
    OSSL_NAMEMAP *namemap = ossl_namemap_stored(methdata->libctx);
#ifdef FIPS_MODULE
    /*
     * The FIPS provider has its own internal library context where only it
     * is loaded.  Consequently, property queries aren't relevant because
     * there is only one fetchable algorithm and it is assumed that the
     * FIPS-ness is handled by the using algorithm.
     */
    const char *const propq = "";
#else
    const char *const propq = properties != NULL ? properties : "";
#endif /* FIPS_MODULE */
    uint32_t meth_id = 0;
    void *method = NULL;
    int unsupported, name_id;

    if (store == NULL || namemap == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    /*
     * If there's ever an operation_id == 0 passed, we have an internal
     * programming error.
     */
    if (!ossl_assert(operation_id > 0)) {
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    /* If we haven't received a name id yet, try to get one for the name */
    name_id = ossl_namemap_name2num(namemap, name);

    /*
     * If we have a name id, calculate a method id with evp_method_id().
     *
     * evp_method_id returns 0 if we have too many operations (more than
     * about 2^8) or too many names (more than about 2^24).  In that case,
     * we can't create any new method.
     * For all intents and purposes, this is an internal error.
     */
    if (name_id != 0 && (meth_id = evp_method_id(name_id, operation_id)) == 0) {
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    /*
     * If we haven't found the name yet, chances are that the algorithm to
     * be fetched is unsupported.
     */
    unsupported = name_id == 0;

    if (meth_id == 0
        || !ossl_method_store_cache_get(store, prov, meth_id, propq, &method)) {
        OSSL_METHOD_CONSTRUCT_METHOD mcm = {
            get_tmp_evp_method_store,
            reserve_evp_method_store,
            unreserve_evp_method_store,
            get_evp_method_from_store,
            put_evp_method_in_store,
            construct_evp_method,
            destruct_evp_method
        };

        methdata->operation_id = operation_id;
        methdata->name_id = name_id;
        methdata->names = name;
        methdata->propquery = propq;
        methdata->method_from_algorithm = new_method;
        methdata->refcnt_up_method = up_ref_method;
        methdata->destruct_method = free_method;
        methdata->flag_construct_error_occurred = 0;
        if ((method = ossl_method_construct(methdata->libctx, operation_id,
                 &prov, 0 /* !force_cache */,
                 &mcm, methdata))
            != NULL) {
            /*
             * If construction did create a method for us, we know that
             * there is a correct name_id and meth_id, since those have
             * already been calculated in get_evp_method_from_store() and
             * put_evp_method_in_store() above.
             * Note that there is a corner case here, in which, if a user
             * passes a name of the form name1:name2:..., then the construction
             * will create a method against all names, but the lookup will fail
             * as ossl_namemap_name2num treats the name string as a single name
             * rather than introducing new features where in the EVP_<obj>_fetch
             * parses the string and queries for each, return an error.
             */
            if (name_id == 0)
                name_id = ossl_namemap_name2num(namemap, name);
            if (name_id == 0) {
                ERR_raise_data(ERR_LIB_EVP, ERR_R_FETCH_FAILED,
                    "Algorithm %s cannot be found", name != NULL ? name : "<null>");
                free_method(method);
                method = NULL;
            } else {
                meth_id = evp_method_id(name_id, operation_id);
                if (meth_id != 0)
                    ossl_method_store_cache_set(store, prov, meth_id, propq,
                        method, up_ref_method, free_method);
            }
        }

        /*
         * If we never were in the constructor, the algorithm to be fetched
         * is unsupported.
         */
        unsupported = !methdata->flag_construct_error_occurred;
    }

    if ((name_id != 0 || name != NULL) && method == NULL) {
        int code = unsupported ? ERR_R_UNSUPPORTED : ERR_R_FETCH_FAILED;

        if (name == NULL)
            name = ossl_namemap_num2name(namemap, name_id, 0);
        ERR_raise_data(ERR_LIB_EVP, code,
            "%s, Algorithm (%s : %d), Properties (%s)",
            ossl_lib_ctx_get_descriptor(methdata->libctx),
            name == NULL ? "<null>" : name, name_id,
            properties == NULL ? "<null>" : properties);
    } else {
        OSSL_TRACE4(QUERY, "%s, Algorithm (%s : %d), Properties (%s)\n",
            ossl_lib_ctx_get_descriptor(methdata->libctx),
            name == NULL ? "<null>" : name, name_id,
            properties == NULL ? "<null>" : properties);
    }

    return method;
}

/**
 * @brief Flush thread-local EVP caches.
 *
 * Increments a global generation counter used to invalidate or refresh
 * thread-local EVP caches. This ensures that cached data is treated as
 * stale and recomputed or cleared on subsequent use.
 *
 * This function is thread-safe and relies on the underlying counter
 * implementation to provide proper synchronization semantics.
 */
void evp_flush_thread_local_caches(void)
{
    tsan_counter(&flush_generation);
}

/**
 * @brief Free an EVP cache object derived from a value.
 *
 * Converts the given value into an EVP cache object of the specified
 * type and then frees it using the corresponding type-specific free
 * function.
 *
 * @param typ The EVP object type (used to resolve helper functions).
 * @param val The value from which to derive the EVP cache object.
 *
 * @note The macro evaluates @p val exactly once.
 * @note The type @p typ must have corresponding functions:
 *       ossl_ht_evpcache_<typ>_from_value() and <typ>_free().
 */
#define TL_FREE(typ, val)                                    \
    do {                                                     \
        typ *evp = ossl_ht_evpcache_##typ##_from_value(val); \
                                                             \
        typ##_free(evp);                                     \
    } while (0)

/**
 * @brief Free all thread-local EVP cache entries for a given value.
 *
 * Releases any cached EVP objects associated with the supplied hash
 * table value across all supported EVP types (e.g., digests, ciphers,
 * MACs, KDFs, RANDs, key management, key exchange, signatures, etc.).
 *
 * Each cache entry is converted from the generic @p val using the
 * appropriate helper and then freed via the corresponding type-specific
 * free function.
 *
 * @param val Pointer to the hash table value containing cached EVP data.
 *
 * @note This function assumes that @p val is valid and compatible with
 *       all EVP cache extraction helpers.
 * @note Intended for internal use when cleaning up thread-local EVP
 *       storage.
 */
static void evp_thread_local_free(HT_VALUE *val)
{
    /*
     * NOTE: We just invoke TL_FREE here for every type as it saves cpu cycles
     * The TL_FREE macro confirms the type of object we're freeing, and returns NULL
     * if the type doesn't match.  The corresponding evp type free function already
     * does a NULL check prior to freeing, so only one of these for any given EVP type
     * will actually do any real free work
     */
    TL_FREE(EVP_MD, val);
    TL_FREE(EVP_CIPHER, val);
    TL_FREE(EVP_MAC, val);
    TL_FREE(EVP_KDF, val);
    TL_FREE(EVP_RAND, val);
    TL_FREE(EVP_KEYMGMT, val);
    TL_FREE(EVP_KEYEXCH, val);
    TL_FREE(EVP_SIGNATURE, val);
    TL_FREE(EVP_ASYM_CIPHER, val);
    TL_FREE(EVP_KEM, val);
    TL_FREE(EVP_SKEYMGMT, val);
}

/**
 * @brief Free the EVP thread-local cache associated with a library context.
 *
 * Retrieves the thread-local EVP cache for the given library context,
 * clears the thread-local reference, and releases all associated
 * resources, including the underlying hash table and cache structure.
 *
 * @param arg Pointer to the OSSL_LIB_CTX for which the thread-local
 *            EVP cache should be freed.
 *
 * @note The @p arg parameter must be a valid OSSL_LIB_CTX pointer.
 * @note After this call, the thread-local cache pointer for the given
 *       context is reset to NULL.
 * @note Intended for use as a thread-local cleanup callback.
 */
static void free_evp_thread_cache(void *arg)
{
    OSSL_LIB_CTX *ctx = arg;
    EVP_THREAD_CACHE *cache = CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_EVP_CACHE_KEY,
        ctx);

    CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_EVP_CACHE_KEY, ctx, NULL);

    ossl_ht_free(cache->cache);
    OPENSSL_free(cache);
}

/**
 * @brief Construct a merged property query string for EVP lookups.
 *
 * Builds a string key incorporating the operation identifier, algorithm
 * name, provider, and an effective property query. The effective query
 * is derived by combining the global default properties from the
 * library context with the supplied property query string.
 *
 * The behavior depends on the presence of global properties and the
 * supplied @p prop:
 * - If both are NULL, only the operation, name, and provider are used.
 * - If only @p prop is non-NULL, it is appended directly.
 * - If only global properties exist, they are serialized and appended.
 * - If both exist, they are parsed, merged, and then serialized.
 *
 * The resulting string is written into @p buf.
 *
 * @param op      Operation identifier (e.g., EVP operation id).
 * @param name    Algorithm name.
 * @param prop    Property query string (may be NULL).
 * @param prov    Provider associated with the implementation.
 * @param ctx     Library context containing global properties.
 * @param buf     Output buffer to receive the constructed string.
 * @param buf_len Size of @p buf in bytes.
 *
 * @return Pointer to @p buf on success, or NULL on failure.
 *
 * @note The output is truncated if it exceeds @p buf_len.
 * @note Temporary property lists are allocated and freed internally.
 * @note The returned string is not a canonical property query, but a
 *       composite key suitable for cache indexing.
 */
static ossl_inline char *merge_default_properties_string(int op, const char *name, const char *prop,
    OSSL_PROVIDER *prov, OSSL_LIB_CTX *ctx, char *buf, size_t buf_len)
{
    OSSL_PROPERTY_LIST *pq = NULL, **gpq = NULL, *pfull = NULL;
    OSSL_PROPERTY_LIST *dummy_gpq = NULL;

    gpq = ossl_ctx_global_properties(ctx, 0);

    memset(buf, 0, buf_len);
    if (gpq == NULL)
        gpq = &dummy_gpq;

    if (*gpq == NULL && prop == NULL) {
        /*
         * Both null, an empty string works here
         */
        snprintf(buf, buf_len, "%d%s%p", op, name, (void *)prov);
        return buf;
    } else if (*gpq == NULL) {
        /*
         * PQ Is not null, so our property string is
         * just the prop_query
         */
        snprintf(buf, buf_len, "%d%s%s%p", op, name, prop, (void *)prov);
        return buf;
    } else if (prop == NULL) {
        /*
         * gpq not null, just need to turn that into a string
         */
        size_t offset;
        offset = snprintf(buf, buf_len, "%d%s%p", op, name, (void *)prov);
        ossl_property_list_to_string(ctx, *gpq, &buf[offset], buf_len - offset);
        return buf;
    } else {
        /*
         * both non-null, need to merge
         */
        size_t offset;
        pq = ossl_parse_query(ctx, prop, 0);
        pfull = ossl_property_merge(pq, *gpq);
        offset = snprintf(buf, buf_len, "%d%s%p", op, name, (void *)prov);
        ossl_property_list_to_string(ctx, pfull, &buf[offset], buf_len - offset);
        ossl_property_free(pfull);
        ossl_property_free(pq);
        return buf;
    }
    return NULL;
}

/*
 * Generic macro to clone and insert all evp types
 * Note: We make ourselves a new refcount here, and set its initial value
 * to 2.  That's one refcount for the hash table, and one for the caller
 *
 * NOTE: Strictly speaking we don't have to clone each algorithm here, but doing so
 * means that we can avoid all the cache line contention that comes with sharing an
 * evp, which gives us a major performance boost.
 */
#define TL_CLONE_AND_INSERT(typ, meth, cache, key, newmeth)                             \
    do {                                                                                \
        typ *evp = (typ *)(meth);                                                       \
        typ *tlevp = OPENSSL_memdup(evp, sizeof(*evp));                                 \
                                                                                        \
        *newmeth = NULL;                                                                \
                                                                                        \
        if (tlevp != NULL) {                                                            \
            if (!CRYPTO_NEW_REF(&tlevp->refcnt, 1)) {                                   \
                OPENSSL_free(tlevp);                                                    \
            } else {                                                                    \
                tlevp->type_name = OPENSSL_strdup(evp->type_name);                      \
                if (tlevp->type_name == NULL) {                                         \
                    CRYPTO_FREE_REF(&tlevp->refcnt);                                    \
                    OPENSSL_free(tlevp);                                                \
                } else {                                                                \
                    typ##_up_ref(tlevp);                                                \
                    if (!ossl_provider_up_ref(tlevp->prov)) {                           \
                        typ##_free(tlevp);                                              \
                        typ##_free(tlevp);                                              \
                    } else {                                                            \
                        if (ossl_ht_evpcache_##typ##_insert((cache), TO_HT_KEY(&(key)), \
                                tlevp, NULL)                                            \
                            <= 0) {                                                     \
                            typ##_free(tlevp);                                          \
                            typ##_free(tlevp);                                          \
                            *newmeth = meth;                                            \
                        } else {                                                        \
                            typ##_free(evp);                                            \
                            *newmeth = tlevp;                                           \
                        }                                                               \
                    }                                                                   \
                }                                                                       \
            }                                                                           \
        }                                                                               \
    } while (0)

/**
 * @brief Store a method in the thread-local EVP cache.
 *
 * Inserts a cloned instance of the supplied method into the thread-local
 * cache associated with the given library context, using a key derived
 * from the merged property string. The stored object is specific to the
 * EVP operation type and can be retrieved for reuse within the same
 * thread.
 *
 * Depending on @p operation_id, the method is cast to the appropriate
 * EVP type, cloned, and inserted into the cache. The returned pointer
 * corresponds to the cached (cloned) instance.
 *
 * @param ctx            Library context associated with the cache.
 * @param c              Pointer to the thread-local cache pointer.
 * @param operation_id   EVP operation identifier (e.g., OSSL_OP_DIGEST).
 * @param merged_props   Key string representing merged properties.
 * @param method         Method to store (type depends on operation).
 *
 * @return Pointer to the cached (cloned) method on success, or the
 *         original @p method if caching is unavailable or fails.
 *
 * @note If the cache is NULL, no insertion is performed and @p method is
 *       returned unchanged.
 * @note The key is derived directly from @p merged_props and must remain
 *       valid for the duration of the operation.
 * @note Cloning and insertion are performed via TL_CLONE_AND_INSERT.
 */
static ossl_inline void *evp_thread_local_store(OSSL_LIB_CTX *ctx,
    EVP_THREAD_CACHE **c, int operation_id,
    const char *merged_props,
    void *method)
{
    EVP_CACHE_KEY key;
    void *ret = method;
    EVP_THREAD_CACHE *cache = *c;
    EVP_MD *md;
    EVP_CIPHER *cph;
    EVP_MAC *mac;
    EVP_KDF *kdf;
    EVP_RAND *rand;
    EVP_KEYMGMT *kmg;
    EVP_KEYEXCH *kex;
    EVP_SIGNATURE *sig;
    EVP_ASYM_CIPHER *acp;
    EVP_KEM *kem;
    EVP_SKEYMGMT *smg;

    if (ossl_unlikely(cache == NULL)) {
        goto err;
    } else {
        HT_INIT_KEY_EXTERNAL(&key, (uint8_t *)merged_props, strlen(merged_props));

        switch (operation_id) {
        case OSSL_OP_DIGEST:
            TL_CLONE_AND_INSERT(EVP_MD, method, cache->cache, key, &md);
            ret = md;
            break;
        case OSSL_OP_CIPHER:
            TL_CLONE_AND_INSERT(EVP_CIPHER, method, cache->cache, key, &cph);
            ret = cph;
            break;
        case OSSL_OP_MAC:
            TL_CLONE_AND_INSERT(EVP_MAC, method, cache->cache, key, &mac);
            ret = mac;
            break;
        case OSSL_OP_KDF:
            TL_CLONE_AND_INSERT(EVP_KDF, method, cache->cache, key, &kdf);
            ret = kdf;
            break;
        case OSSL_OP_RAND:
            TL_CLONE_AND_INSERT(EVP_RAND, method, cache->cache, key, &rand);
            ret = rand;
            break;
        case OSSL_OP_KEYMGMT:
            TL_CLONE_AND_INSERT(EVP_KEYMGMT, method, cache->cache, key, &kmg);
            ret = kmg;
            break;
        case OSSL_OP_KEYEXCH:
            TL_CLONE_AND_INSERT(EVP_KEYEXCH, method, cache->cache, key, &kex);
            ret = kex;
            break;
        case OSSL_OP_SIGNATURE:
            TL_CLONE_AND_INSERT(EVP_SIGNATURE, method, cache->cache, key, &sig);
            ret = sig;
            break;
        case OSSL_OP_ASYM_CIPHER:
            TL_CLONE_AND_INSERT(EVP_ASYM_CIPHER, method, cache->cache, key, &acp);
            ret = acp;
            break;
        case OSSL_OP_KEM:
            TL_CLONE_AND_INSERT(EVP_KEM, method, cache->cache, key, &kem);
            ret = kem;
            break;
        case OSSL_OP_SKEYMGMT:
            TL_CLONE_AND_INSERT(EVP_SKEYMGMT, method, cache->cache, key, &smg);
            ret = smg;
            break;
        default:
            break;
        }
    }
err:
    return ret;
}

/**
 * @brief Fetch a method from the thread-local EVP cache.
 *
 * Looks up a cached EVP method corresponding to the given operation
 * and merged property string within the thread-local cache associated
 * with the specified library context.
 *
 * If the cache does not yet exist for the current thread and context,
 * it is created, initialized, and registered for thread cleanup. In
 * that case, no lookup is performed and NULL is returned.
 *
 * If the global flush generation has changed since the cache was last
 * used, the cache is cleared before performing any lookup.
 *
 * On a successful lookup, the returned method's reference count is
 * incremented (non-atomically, as the cache is thread-local).
 *
 * @param ctx            Library context associated with the cache.
 * @param c              Pointer to the thread-local cache pointer.
 * @param operation_id   EVP operation identifier (e.g., OSSL_OP_DIGEST).
 * @param merged_props   Key string representing merged properties.
 *
 * @return Pointer to the cached method on success, or NULL if no cached
 *         entry exists or if initialization fails.
 *
 * @note Cache initialization occurs lazily on first use per thread.
 * @note Cache entries are invalidated when the global flush generation
 *       changes.
 * @note The key is derived directly from @p merged_props and must be a
 *       stable string for correct lookup behavior.
 * @note Reference counts are incremented without atomic operations due
 *       to thread-local isolation.
 */
static ossl_inline void *evp_thread_local_fetch(OSSL_LIB_CTX *ctx,
    EVP_THREAD_CACHE **c, int operation_id, const char *merged_props)
{
    EVP_CACHE_KEY key;
    void *ret = NULL;
    EVP_THREAD_CACHE *cache = *c;
    EVP_MD *md;
    EVP_CIPHER *cph;
    EVP_MAC *mac;
    EVP_KDF *kdf;
    EVP_RAND *rand;
    EVP_KEYMGMT *kmg;
    EVP_KEYEXCH *kex;
    EVP_SIGNATURE *sig;
    EVP_ASYM_CIPHER *acp;
    EVP_KEM *kem;
    EVP_SKEYMGMT *smg;

    ctx = ossl_lib_ctx_get_concrete(ctx);

    if (ctx == NULL)
        return NULL;
    /*
     * In the nominal case this will be true at most once
     */
    if (ossl_unlikely(cache == NULL)) {
        HT_CONFIG conf = {
            .ctx = ctx,
            .ht_free_fn = evp_thread_local_free,
            .ht_hash_fn = NULL,
            .init_neighborhoods = 0,
            .collision_check = 1,
            .lockless_reads = 0,
            .no_rcu = 1
        };

        cache = OPENSSL_zalloc(sizeof(EVP_THREAD_CACHE));
        if (cache == NULL)
            goto err;

        cache->cache = ossl_ht_new(&conf);
        if (cache->cache == NULL) {
            OPENSSL_free(cache);
            goto err;
        }
        if (!CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_EVP_CACHE_KEY,
                ctx, cache)) {
            ossl_ht_free(cache->cache);
            OPENSSL_free(cache);
            goto err;
        }
        if (!ossl_init_thread_start(NULL, ctx, free_evp_thread_cache)) {
            CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_EVP_CACHE_KEY,
                ctx, NULL);
            ossl_ht_free(cache->cache);
            OPENSSL_free(cache);
            goto err;
        }

        *c = cache;

        /*
         * On cache creation, its empty, so always return null here
         * by jumping to err;
         */
        goto err;
    } else {
        HT_VALUE *v = NULL;
        int current_flush_gen = tsan_load(&flush_generation);

        if (current_flush_gen != cache->flush_generation) {
            ossl_ht_flush(cache->cache);
            cache->flush_generation = current_flush_gen;
            goto err;
        }

        HT_INIT_KEY_EXTERNAL(&key, (uint8_t *)merged_props, strlen(merged_props));
        switch (operation_id) {
        case OSSL_OP_DIGEST:
            md = ossl_ht_evpcache_EVP_MD_get(cache->cache, TO_HT_KEY(&key), &v);
            if (md != NULL) {
                /* We don't need to atomically mutate refcnt when its thread local */
                md->refcnt.val++;
            }
            ret = md;
            break;
        case OSSL_OP_CIPHER:
            cph = ossl_ht_evpcache_EVP_CIPHER_get(cache->cache, TO_HT_KEY(&key), &v);
            if (cph != NULL)
                cph->refcnt.val++;
            ret = cph;
            break;
        case OSSL_OP_MAC:
            mac = ossl_ht_evpcache_EVP_MAC_get(cache->cache, TO_HT_KEY(&key), &v);
            if (mac != NULL)
                mac->refcnt.val++;
            ret = mac;
            break;
        case OSSL_OP_KDF:
            kdf = ossl_ht_evpcache_EVP_KDF_get(cache->cache, TO_HT_KEY(&key), &v);
            if (kdf != NULL)
                kdf->refcnt.val++;
            ret = kdf;
            break;
        case OSSL_OP_RAND:
            rand = ossl_ht_evpcache_EVP_RAND_get(cache->cache, TO_HT_KEY(&key), &v);
            if (rand != NULL)
                rand->refcnt.val++;
            ret = rand;
            break;
        case OSSL_OP_KEYMGMT:
            kmg = ossl_ht_evpcache_EVP_KEYMGMT_get(cache->cache, TO_HT_KEY(&key), &v);
            if (kmg != NULL)
                kmg->refcnt.val++;
            ret = kmg;
            break;
        case OSSL_OP_KEYEXCH:
            kex = ossl_ht_evpcache_EVP_KEYEXCH_get(cache->cache, TO_HT_KEY(&key), &v);
            if (kex != NULL)
                kex->refcnt.val++;
            ret = kex;
            break;
        case OSSL_OP_SIGNATURE:
            sig = ossl_ht_evpcache_EVP_SIGNATURE_get(cache->cache, TO_HT_KEY(&key), &v);
            if (sig != NULL)
                sig->refcnt.val++;
            ret = sig;
            break;
        case OSSL_OP_ASYM_CIPHER:
            acp = ossl_ht_evpcache_EVP_ASYM_CIPHER_get(cache->cache, TO_HT_KEY(&key), &v);
            if (acp != NULL)
                acp->refcnt.val++;
            ret = acp;
            break;
        case OSSL_OP_KEM:
            kem = ossl_ht_evpcache_EVP_KEM_get(cache->cache, TO_HT_KEY(&key), &v);
            if (kem != NULL)
                kem->refcnt.val++;
            ret = kem;
            break;
        case OSSL_OP_SKEYMGMT:
            smg = ossl_ht_evpcache_EVP_SKEYMGMT_get(cache->cache, TO_HT_KEY(&key), &v);
            if (smg != NULL)
                smg->refcnt.val++;
            ret = smg;
            break;
        default:
            break;
        }
    }
err:
    return ret;
}

void *evp_generic_fetch(OSSL_LIB_CTX *libctx, int operation_id,
    const char *name, const char *properties,
    void *(*new_method)(int name_id,
        const OSSL_ALGORITHM *algodef,
        OSSL_PROVIDER *prov),
    int (*up_ref_method)(void *),
    void (*free_method)(void *))
{
    EVP_THREAD_CACHE *cache = CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_EVP_CACHE_KEY,
        libctx);
    struct evp_method_data_st methdata;
    char buf[512];
    const char *merged_props = merge_default_properties_string(operation_id, name,
        properties, NULL, libctx, buf, 512);
    void *method = evp_thread_local_fetch(libctx, &cache, operation_id, merged_props);

    if (method != NULL)
        return method;

    methdata.libctx = libctx;
    methdata.tmp_store = NULL;
    method = inner_evp_generic_fetch(&methdata, NULL, operation_id,
        name, properties,
        new_method, up_ref_method, free_method);
    dealloc_tmp_evp_method_store(methdata.tmp_store);
    if (method != NULL)
        method = evp_thread_local_store(libctx, &cache, operation_id, merged_props, method);
    return method;
}

/*
 * evp_generic_fetch_from_prov() is special, and only returns methods from
 * the given provider.
 * This is meant to be used when one method needs to fetch an associated
 * method.
 */
void *evp_generic_fetch_from_prov(OSSL_PROVIDER *prov, int operation_id,
    const char *name, const char *properties,
    void *(*new_method)(int name_id,
        const OSSL_ALGORITHM *algodef,
        OSSL_PROVIDER *prov),
    int (*up_ref_method)(void *),
    void (*free_method)(void *))
{
    struct evp_method_data_st methdata;
    void *method;
    char buf[512];
    EVP_THREAD_CACHE *cache = CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_EVP_CACHE_KEY,
        ossl_provider_libctx(prov));
    const char *merged_props = merge_default_properties_string(operation_id, name,
        properties, prov, ossl_provider_libctx(prov), buf, 512);

    method = evp_thread_local_fetch(ossl_provider_libctx(prov), &cache, operation_id, merged_props);

    if (method != NULL)
        return method;

    methdata.libctx = ossl_provider_libctx(prov);
    methdata.tmp_store = NULL;
    method = inner_evp_generic_fetch(&methdata, prov, operation_id,
        name, properties,
        new_method, up_ref_method, free_method);
    dealloc_tmp_evp_method_store(methdata.tmp_store);
    if (method != NULL)
        method = evp_thread_local_store(ossl_provider_libctx(prov), &cache, operation_id, merged_props, method);
    return method;
}

int evp_method_store_cache_flush(OSSL_LIB_CTX *libctx)
{
    OSSL_METHOD_STORE *store = get_evp_method_store(libctx);

    if (store != NULL)
        return ossl_method_store_cache_flush_all(store);
    return 1;
}

int evp_method_store_remove_all_provided(const OSSL_PROVIDER *prov)
{
    OSSL_LIB_CTX *libctx = ossl_provider_libctx(prov);
    OSSL_METHOD_STORE *store = get_evp_method_store(libctx);

    if (store != NULL)
        return ossl_method_store_remove_all_provided(store, prov);
    return 1;
}

static int evp_set_parsed_default_properties(OSSL_LIB_CTX *libctx,
    OSSL_PROPERTY_LIST *def_prop,
    int loadconfig,
    int mirrored)
{
    OSSL_METHOD_STORE *store = get_evp_method_store(libctx);
    OSSL_PROPERTY_LIST **plp = ossl_ctx_global_properties(libctx, loadconfig);

    if (plp != NULL && store != NULL) {
        int ret;
#ifndef FIPS_MODULE
        char *propstr = NULL;
        size_t strsz;

        if (mirrored) {
            if (ossl_global_properties_no_mirrored(libctx))
                return 0;
        } else {
            /*
             * These properties have been explicitly set on this libctx, so
             * don't allow any mirroring from a parent libctx.
             */
            ossl_global_properties_stop_mirroring(libctx);
        }

        strsz = ossl_property_list_to_string(libctx, def_prop, NULL, 0);
        if (strsz > 0)
            propstr = OPENSSL_malloc(strsz);
        if (propstr == NULL) {
            ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (ossl_property_list_to_string(libctx, def_prop, propstr,
                strsz)
            == 0) {
            OPENSSL_free(propstr);
            ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        ossl_provider_default_props_update(libctx, propstr);
        OPENSSL_free(propstr);
#endif
        ossl_property_free(*plp);
        *plp = def_prop;

        ret = ossl_method_store_cache_flush_all(store);
#ifndef FIPS_MODULE
        ossl_decoder_cache_flush(libctx);
#endif
        return ret;
    }
    ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
    return 0;
}

int evp_set_default_properties_int(OSSL_LIB_CTX *libctx, const char *propq,
    int loadconfig, int mirrored)
{
    OSSL_PROPERTY_LIST *pl = NULL;

    if (propq != NULL && (pl = ossl_parse_query(libctx, propq, 1)) == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_DEFAULT_QUERY_PARSE_ERROR);
        return 0;
    }
    if (!evp_set_parsed_default_properties(libctx, pl, loadconfig, mirrored)) {
        ossl_property_free(pl);
        return 0;
    }
    return 1;
}

int EVP_set_default_properties(OSSL_LIB_CTX *libctx, const char *propq)
{
    return evp_set_default_properties_int(libctx, propq, 1, 0);
}

static int evp_default_properties_merge(OSSL_LIB_CTX *libctx, const char *propq,
    int loadconfig)
{
    OSSL_PROPERTY_LIST **plp = ossl_ctx_global_properties(libctx, loadconfig);
    OSSL_PROPERTY_LIST *pl1, *pl2;

    if (propq == NULL)
        return 1;
    if (plp == NULL || *plp == NULL)
        return evp_set_default_properties_int(libctx, propq, 0, 0);
    if ((pl1 = ossl_parse_query(libctx, propq, 1)) == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_DEFAULT_QUERY_PARSE_ERROR);
        return 0;
    }
    pl2 = ossl_property_merge(pl1, *plp);
    ossl_property_free(pl1);
    if (pl2 == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_CRYPTO_LIB);
        return 0;
    }
    if (!evp_set_parsed_default_properties(libctx, pl2, 0, 0)) {
        ossl_property_free(pl2);
        return 0;
    }
    return 1;
}

static int evp_default_property_is_enabled(OSSL_LIB_CTX *libctx,
    const char *prop_name)
{
    OSSL_PROPERTY_LIST **plp = ossl_ctx_global_properties(libctx, 1);

    return plp != NULL && ossl_property_is_enabled(libctx, prop_name, *plp);
}

int EVP_default_properties_is_fips_enabled(OSSL_LIB_CTX *libctx)
{
    return evp_default_property_is_enabled(libctx, "fips");
}

int evp_default_properties_enable_fips_int(OSSL_LIB_CTX *libctx, int enable,
    int loadconfig)
{
    const char *query = (enable != 0) ? "fips=yes" : "-fips";

    return evp_default_properties_merge(libctx, query, loadconfig);
}

int EVP_default_properties_enable_fips(OSSL_LIB_CTX *libctx, int enable)
{
    return evp_default_properties_enable_fips_int(libctx, enable, 1);
}

char *evp_get_global_properties_str(OSSL_LIB_CTX *libctx, int loadconfig)
{
    OSSL_PROPERTY_LIST **plp = ossl_ctx_global_properties(libctx, loadconfig);
    char *propstr = NULL;
    size_t sz;

    if (plp == NULL)
        return OPENSSL_strdup("");

    sz = ossl_property_list_to_string(libctx, *plp, NULL, 0);
    if (sz == 0) {
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    propstr = OPENSSL_malloc(sz);
    if (propstr == NULL)
        return NULL;
    if (ossl_property_list_to_string(libctx, *plp, propstr, sz) == 0) {
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        OPENSSL_free(propstr);
        return NULL;
    }
    return propstr;
}

char *EVP_get1_default_properties(OSSL_LIB_CTX *libctx)
{
    return evp_get_global_properties_str(libctx, ossl_lib_ctx_is_global_default(libctx));
}

struct filter_data_st {
    int operation_id;
    void (*user_fn)(void *method, void *arg);
    void *user_arg;
};

static void filter_on_operation_id(int id, void *method, void *arg)
{
    struct filter_data_st *data = arg;

    if ((id & METHOD_ID_OPERATION_MASK) == data->operation_id)
        data->user_fn(method, data->user_arg);
}

void evp_generic_do_all(OSSL_LIB_CTX *libctx, int operation_id,
    void (*user_fn)(void *method, void *arg),
    void *user_arg,
    void *(*new_method)(int name_id,
        const OSSL_ALGORITHM *algodef,
        OSSL_PROVIDER *prov),
    int (*up_ref_method)(void *),
    void (*free_method)(void *))
{
    struct evp_method_data_st methdata;
    struct filter_data_st data;

    methdata.libctx = libctx;
    methdata.tmp_store = NULL;
    (void)inner_evp_generic_fetch(&methdata, NULL, operation_id, NULL, NULL,
        new_method, up_ref_method, free_method);

    data.operation_id = operation_id;
    data.user_fn = user_fn;
    data.user_arg = user_arg;
    if (methdata.tmp_store != NULL)
        ossl_method_store_do_all(methdata.tmp_store, &filter_on_operation_id,
            &data);
    ossl_method_store_do_all(get_evp_method_store(libctx),
        &filter_on_operation_id, &data);
    dealloc_tmp_evp_method_store(methdata.tmp_store);
}

int evp_is_a(OSSL_PROVIDER *prov, int number,
    const char *legacy_name, const char *name)
{
    /*
     * For a |prov| that is NULL, the library context will be NULL
     */
    OSSL_LIB_CTX *libctx = ossl_provider_libctx(prov);
    OSSL_NAMEMAP *namemap = ossl_namemap_stored(libctx);

    if (prov == NULL)
        number = ossl_namemap_name2num(namemap, legacy_name);
    return ossl_namemap_name2num(namemap, name) == number;
}

int evp_names_do_all(OSSL_PROVIDER *prov, int number,
    void (*fn)(const char *name, void *data),
    void *data)
{
    OSSL_LIB_CTX *libctx = ossl_provider_libctx(prov);
    OSSL_NAMEMAP *namemap = ossl_namemap_stored(libctx);

    return ossl_namemap_doall_names(namemap, number, fn, data);
}
