#include <string.h>
#include <stdio.h>

#include <openssl/opensslconf.h>
#include <openssl/safestack.h>
#include <openssl/lhash.h>
#include <openssl/err.h>
#include <openssl/store.h>
#include <openssl/store_cache.h>
#include "store_locl.h"

struct ossl_store_cache_st {
    LHASH_OF(CACHE_ENTRY) *entries;
};

static unsigned long cache_hash(const CACHE_ENTRY *v)
{
    return OPENSSL_LH_strhash(v->uri);
}

static int cache_cmp(const CACHE_ENTRY *a, const CACHE_ENTRY *b)
{
    return strcmp(a->uri, b->uri);
}

OSSL_STORE_CACHE *OSSL_STORE_CACHE_new(void)
{
    OSSL_STORE_CACHE *cache = OPENSSL_zalloc(sizeof(*cache));

    if (cache == NULL
        || ((cache->entries = lh_CACHE_ENTRY_new(cache_hash, cache_cmp))
            == NULL)) {
        OSSL_STOREerr(OSSL_STORE_F_OSSL_STORE_CACHE_NEW,ERR_R_MALLOC_FAILURE);
        OSSL_STORE_CACHE_free(cache);
        return NULL;
    }

#ifdef DEBUG_OSSL_STORE_CACHE
    fprintf(stderr, "Created new OSSL_STORE_CACHE: %p (%p)\n",
            (void *)cache, (void *)cache->entries);
#endif

    return cache;
}

IMPLEMENT_LHASH_DOALL_ARG(CACHE_ENTRY, void);
static void free_entry(CACHE_ENTRY *entry, void *dummy)
{
    sk_OSSL_STORE_INFO_pop_free(entry->infos, OSSL_STORE_INFO_free);
    OPENSSL_free(entry->uri);
    OPENSSL_free(entry);
}

void OSSL_STORE_CACHE_free(OSSL_STORE_CACHE *cache)
{
    if (cache != NULL) {
#ifdef DEBUG_OSSL_STORE_CACHE
        fprintf(stderr, "Removing OSSL_STORE_CACHE: %p (%p)\n",
                (void *)cache, (void *)cache->entries);
        OPENSSL_LH_stats((OPENSSL_LHASH *)cache->entries, stderr);
        OPENSSL_LH_node_stats((OPENSSL_LHASH *)cache->entries, stderr);
        OPENSSL_LH_node_usage_stats((OPENSSL_LHASH *)cache->entries, stderr);
#endif
        lh_CACHE_ENTRY_doall_void(cache->entries, free_entry, NULL);
        lh_CACHE_ENTRY_free(cache->entries);
        OPENSSL_free(cache);
    }
}

struct ossl_store_loader_ctx_st {
    /* The cache entry we're currently working with */
    CACHE_ENTRY *entry;

    /* Only used by cache_loader */
    OSSL_STORE_CTX *storectx;

    /* Error indicator */
    int error;
};

static int cache_ctrl(OSSL_STORE_LOADER_CTX *ctx, int cmd, va_list args)
{
    return OSSL_STORE_vctrl(ctx->storectx, cmd, args);
}

static int cache_expect(OSSL_STORE_LOADER_CTX *ctx, int expected)
{
    return OSSL_STORE_expect(ctx->storectx, expected);
}

static int cache_find(OSSL_STORE_LOADER_CTX *ctx, OSSL_STORE_SEARCH *criteria)
{
    return OSSL_STORE_find(ctx->storectx, criteria);
}

static OSSL_STORE_INFO *cache_load(OSSL_STORE_LOADER_CTX *ctx,
                                   const UI_METHOD *ui_method, void *ui_data)
{
    OSSL_STORE_INFO *result = NULL;

    if ((result = OSSL_STORE_load(ctx->storectx)) == NULL)
        return NULL;
    if (OSSL_STORE_INFO_up_ref(result)
        && sk_OSSL_STORE_INFO_push(ctx->entry->infos, result) >= 0)
        return result;

    OSSL_STOREerr(OSSL_STORE_F_CACHE_LOAD, ERR_R_MALLOC_FAILURE);
    OSSL_STORE_INFO_free(result);
    ctx->error = 1;
    return NULL;
}

static int cache_eof(OSSL_STORE_LOADER_CTX *ctx)
{
    return OSSL_STORE_eof(ctx->storectx);
}

static int cache_error(OSSL_STORE_LOADER_CTX *ctx)
{
    return ctx->error || OSSL_STORE_error(ctx->storectx);
}

static int cache_close(OSSL_STORE_LOADER_CTX *ctx)
{
    int result = OSSL_STORE_close(ctx->storectx);

    OPENSSL_free(ctx);
    return result;
}

static const OSSL_STORE_LOADER cache_loader =
    {
        "cache+",
        NULL,                    /* no engine */
        NULL,                    /* no opener */
        cache_ctrl,
        cache_expect,
        cache_find,
        cache_load,
        cache_eof,
        cache_error,
        cache_close
    };

static OSSL_STORE_INFO *pop_load(OSSL_STORE_LOADER_CTX *ctx,
                                 const UI_METHOD *ui_method, void *ui_data)
{
    OSSL_STORE_INFO *result = NULL;

    if ((result = sk_OSSL_STORE_INFO_shift(ctx->entry->infos)) != NULL
        && OSSL_STORE_INFO_up_ref(result))
        return result;

    return NULL;
}

static int pop_eof(OSSL_STORE_LOADER_CTX *ctx)
{
    return sk_OSSL_STORE_INFO_num(ctx->entry->infos) == 0;
}

static int pop_error(OSSL_STORE_LOADER_CTX *ctx)
{
    return 0;
}

static int pop_close(OSSL_STORE_LOADER_CTX *ctx)
{
    sk_OSSL_STORE_INFO_free(ctx->entry->infos);
    OPENSSL_free(ctx->entry->uri);
    OPENSSL_free(ctx->entry);
    OPENSSL_free(ctx);
    return 1;
}

static const OSSL_STORE_LOADER pop_loader =
    {
        "cache+",
        NULL,                    /* no engine */
        NULL,                    /* no opener */
        NULL,                    /* no ctrl */
        NULL,                    /* no expect */
        NULL,                    /* no find */
        pop_load,
        pop_eof,
        pop_error,
        pop_close
    };


OSSL_STORE_CTX *OSSL_STORE_CACHED_open(OSSL_STORE_CACHE *cache, const char *uri,
                                       uint32_t flags,
                                       const UI_METHOD *ui_method,
                                       void *ui_data,
                                       OSSL_STORE_post_process_info_fn
                                       post_process, void *post_process_data)
{
    OSSL_STORE_CTX *ctx = NULL;
    OSSL_STORE_LOADER_CTX *cachectx = NULL;
    CACHE_ENTRY *entry = NULL, template;

    if ((cachectx = OPENSSL_zalloc(sizeof(*cachectx))) == NULL
        || (template.uri = OPENSSL_strdup(uri)) == NULL) {
        OSSL_STOREerr(OSSL_STORE_F_OSSL_STORE_CACHED_OPEN,
                      ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if ((entry = lh_CACHE_ENTRY_retrieve(cache->entries, &template)) == NULL) {
        /* This is a different kind of OSSL_STORE_CTX */
        OSSL_STORE_CTX *storectx = NULL;

        if ((flags & OSSL_STORE_CACHE_FLAG_CACHE_ONLY) != 0) {
            OSSL_STOREerr(OSSL_STORE_F_OSSL_STORE_CACHED_OPEN,
                          OSSL_STORE_R_URI_NOT_IN_CACHE);
            goto err;
        }

        if ((ctx = ossl_store_ctx_new(&cache_loader, cachectx, ui_method,
                                      ui_data, post_process,
                                      post_process_data)) == NULL
            || (entry = OPENSSL_zalloc(sizeof(*entry))) == NULL
            || (entry->uri = template.uri,
                entry->infos = sk_OSSL_STORE_INFO_new_null()) == NULL
            || (lh_CACHE_ENTRY_insert(cache->entries, entry) == NULL
                && lh_CACHE_ENTRY_error(cache->entries) > 0)) {
            OSSL_STOREerr(OSSL_STORE_F_OSSL_STORE_CACHED_OPEN,
                          ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if ((storectx = OSSL_STORE_open(uri, ui_method, ui_data, post_process,
                                        post_process_data)) == NULL)
            goto err;

        cachectx->entry = entry;
        cachectx->storectx = storectx;
    } else {
        CACHE_ENTRY *dupentry = NULL;

        if ((ctx = ossl_store_ctx_new(&pop_loader, cachectx, ui_method, ui_data,
                                      post_process, post_process_data)) == NULL
            || (dupentry = OPENSSL_zalloc(sizeof(*dupentry))) == NULL
            || (dupentry->infos =
                sk_OSSL_STORE_INFO_dup(entry->infos)) == NULL) {
            OSSL_STOREerr(OSSL_STORE_F_OSSL_STORE_CACHED_OPEN,
                          ERR_R_MALLOC_FAILURE);
            goto err;
        }
        dupentry->uri = template.uri;

        cachectx->entry = dupentry;
    }
    return ctx;
 err:
    if (entry != NULL)
        sk_OSSL_STORE_INFO_free(entry->infos);
    OPENSSL_free(template.uri);
    OPENSSL_free(entry);
    OPENSSL_free(cachectx);
    OPENSSL_free(ctx);
    return NULL;
}
